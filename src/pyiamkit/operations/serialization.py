"""Canonical JSON wire format for distributed operational state."""

import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthorizationReason,
    AuthorizationResult,
    GovernanceRuleId,
    RoleBindingId,
    RoleId,
)
from pyiamkit.shared import EntityId
from pyiamkit.tenancy import MembershipId, TenantId

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
)
from .errors import OperationalSerializationError
from .invalidation import InvalidationEvent, InvalidationKind
from .revocation import RevocationMarker, RevocationTargetType
from .state import SecurityStateStamp, StateVersion

_SCHEMA_VERSION = 1


class OperationalJsonCodec:
    """Strict versioned JSON codec for Redis-facing operational payloads."""

    schema_version = _SCHEMA_VERSION

    def encode_security_state(self, stamp: SecurityStateStamp) -> bytes:
        return self._encode("security_state_stamp", _state_to_payload(stamp))

    def decode_security_state(self, data: bytes) -> SecurityStateStamp:
        payload = self._decode(data, "security_state_stamp")
        try:
            return _state_from_payload(payload)
        except (ValueError, TypeError) as exc:
            raise OperationalSerializationError(
                "Security state payload contains invalid domain values."
            ) from exc

    def encode_authorization_cache_entry(self, entry: AuthorizationCacheEntry) -> bytes:
        return self._encode("authorization_cache_entry", _cache_entry_to_payload(entry))

    def decode_authorization_cache_entry(self, data: bytes) -> AuthorizationCacheEntry:
        payload = self._decode(data, "authorization_cache_entry")
        return _cache_entry_from_payload(payload)

    def encode_revocation_marker(self, marker: RevocationMarker) -> bytes:
        return self._encode("revocation_marker", _revocation_to_payload(marker))

    def decode_revocation_marker(self, data: bytes) -> RevocationMarker:
        payload = self._decode(data, "revocation_marker")
        return _revocation_from_payload(payload)

    def encode_invalidation_event(self, event: InvalidationEvent) -> bytes:
        return self._encode("invalidation_event", _invalidation_to_payload(event))

    def decode_invalidation_event(self, data: bytes) -> InvalidationEvent:
        payload = self._decode(data, "invalidation_event")
        return _invalidation_from_payload(payload)

    @staticmethod
    def _encode(payload_type: str, payload: dict[str, object]) -> bytes:
        envelope: dict[str, object] = {
            "payload": payload,
            "payload_type": payload_type,
            "schema_version": _SCHEMA_VERSION,
        }
        return json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    @staticmethod
    def _decode(data: bytes, expected_type: str) -> dict[str, object]:
        if not isinstance(data, bytes):
            raise TypeError("Operational payload must be bytes")
        try:
            raw = cast(
                object,
                json.loads(
                    data.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_pairs,
                    parse_constant=_reject_json_constant,
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OperationalSerializationError(
                "Operational payload is not valid UTF-8 JSON."
            ) from exc
        envelope = _require_mapping(raw, "envelope")
        _require_exact_keys(
            envelope,
            {"payload", "payload_type", "schema_version"},
            context="envelope",
        )
        version = _require_int(envelope, "schema_version")
        if version != _SCHEMA_VERSION:
            raise OperationalSerializationError(
                f"Unsupported operational schema_version: {version}."
            )
        payload_type = _require_str(envelope, "payload_type")
        if payload_type != expected_type:
            raise OperationalSerializationError(
                f"Unexpected operational payload_type: {payload_type!r}."
            )
        return _require_mapping(envelope["payload"], "payload")


def _state_to_payload(stamp: SecurityStateStamp) -> dict[str, object]:
    return {
        "authentication": stamp.authentication.value,
        "global_authorization": stamp.global_authorization.value,
        "governance": stamp.governance.value,
        "identity": stamp.identity.value,
        "membership": stamp.membership.value,
        "runtime_generation": stamp.runtime_generation.value,
        "subject_authorization": stamp.subject_authorization.value,
        "tenant": stamp.tenant.value,
        "tenant_authorization": stamp.tenant_authorization.value,
    }


def _state_from_payload(payload: dict[str, object]) -> SecurityStateStamp:
    expected = {
        "authentication",
        "global_authorization",
        "governance",
        "identity",
        "membership",
        "runtime_generation",
        "subject_authorization",
        "tenant",
        "tenant_authorization",
    }
    _require_exact_keys(payload, expected, context="security_state_stamp")
    return SecurityStateStamp(
        runtime_generation=StateVersion(_require_int(payload, "runtime_generation")),
        identity=StateVersion(_require_int(payload, "identity")),
        tenant=StateVersion(_require_int(payload, "tenant")),
        membership=StateVersion(_require_int(payload, "membership")),
        subject_authorization=StateVersion(_require_int(payload, "subject_authorization")),
        tenant_authorization=StateVersion(_require_int(payload, "tenant_authorization")),
        global_authorization=StateVersion(_require_int(payload, "global_authorization")),
        governance=StateVersion(_require_int(payload, "governance")),
        authentication=StateVersion(_require_int(payload, "authentication")),
    )


def _cache_entry_to_payload(entry: AuthorizationCacheEntry) -> dict[str, object]:
    decision = entry.decision
    return {
        "cached_at": _datetime_to_wire(entry.cached_at),
        "decision": {
            "bound_role_id": _id_to_wire(decision.bound_role_id),
            "explanation_path": list(decision.explanation_path),
            "matched_binding_id": _id_to_wire(decision.matched_binding_id),
            "matched_membership_id": _id_to_wire(decision.matched_membership_id),
            "matched_role_id": _id_to_wire(decision.matched_role_id),
            "matched_rule_id": _id_to_wire(decision.matched_rule_id),
            "reason_code": decision.reason_code.value,
            "required_assurance_level": (
                None
                if decision.required_assurance_level is None
                else decision.required_assurance_level.value
            ),
            "required_mfa": decision.required_mfa,
            "result": decision.result.value,
            "valid_until": (
                None if decision.valid_until is None else _datetime_to_wire(decision.valid_until)
            ),
        },
        "expires_at": _datetime_to_wire(entry.expires_at),
        "key": entry.key.digest,
        "state_stamp": _state_to_payload(entry.state_stamp),
    }


def _cache_entry_from_payload(payload: dict[str, object]) -> AuthorizationCacheEntry:
    _require_exact_keys(
        payload,
        {"cached_at", "decision", "expires_at", "key", "state_stamp"},
        context="authorization_cache_entry",
    )
    decision_payload = _require_mapping(payload["decision"], "authorization_cache_entry.decision")
    _require_exact_keys(
        decision_payload,
        {
            "bound_role_id",
            "explanation_path",
            "matched_binding_id",
            "matched_membership_id",
            "matched_role_id",
            "matched_rule_id",
            "reason_code",
            "required_assurance_level",
            "required_mfa",
            "result",
            "valid_until",
        },
        context="authorization_cache_entry.decision",
    )
    explanation_raw = decision_payload["explanation_path"]
    if not isinstance(explanation_raw, list) or not all(
        isinstance(item, str) for item in explanation_raw
    ):
        raise OperationalSerializationError(
            "authorization_cache_entry.decision.explanation_path must be a list of strings."
        )
    required_mfa_raw = decision_payload["required_mfa"]
    if required_mfa_raw is not None and not isinstance(required_mfa_raw, bool):
        raise OperationalSerializationError(
            "authorization_cache_entry.decision.required_mfa must be boolean or null."
        )
    assurance_raw = _optional_str(decision_payload, "required_assurance_level")
    valid_until_raw = _optional_str(decision_payload, "valid_until")
    try:
        decision = CachedAuthorizationDecision(
            result=AuthorizationResult(_require_str(decision_payload, "result")),
            reason_code=AuthorizationReason(_require_str(decision_payload, "reason_code")),
            valid_until=(None if valid_until_raw is None else _datetime_from_wire(valid_until_raw)),
            matched_membership_id=_optional_entity_id(
                decision_payload,
                "matched_membership_id",
                MembershipId,
            ),
            bound_role_id=_optional_entity_id(decision_payload, "bound_role_id", RoleId),
            matched_binding_id=_optional_entity_id(
                decision_payload,
                "matched_binding_id",
                RoleBindingId,
            ),
            matched_role_id=_optional_entity_id(decision_payload, "matched_role_id", RoleId),
            matched_rule_id=_optional_entity_id(
                decision_payload,
                "matched_rule_id",
                GovernanceRuleId,
            ),
            required_assurance_level=(
                None if assurance_raw is None else AssuranceLevel(assurance_raw)
            ),
            required_mfa=required_mfa_raw,
            explanation_path=tuple(cast(list[str], explanation_raw)),
        )
        return AuthorizationCacheEntry(
            key=AuthorizationCacheKey(_require_str(payload, "key")),
            decision=decision,
            state_stamp=_state_from_payload(
                _require_mapping(payload["state_stamp"], "authorization_cache_entry.state_stamp")
            ),
            cached_at=_datetime_from_wire(_require_str(payload, "cached_at")),
            expires_at=_datetime_from_wire(_require_str(payload, "expires_at")),
        )
    except (ValueError, TypeError) as exc:
        raise OperationalSerializationError(
            "Authorization cache payload contains invalid domain values."
        ) from exc


def _revocation_to_payload(marker: RevocationMarker) -> dict[str, object]:
    return {
        "expires_at": None if marker.expires_at is None else _datetime_to_wire(marker.expires_at),
        "reason_code": marker.reason_code,
        "revoked_at": _datetime_to_wire(marker.revoked_at),
        "source_version": None if marker.source_version is None else marker.source_version.value,
        "target_id": marker.target_id,
        "target_type": marker.target_type.value,
        "tenant_id": _id_to_wire(marker.tenant_id),
    }


def _revocation_from_payload(payload: dict[str, object]) -> RevocationMarker:
    _require_exact_keys(
        payload,
        {
            "expires_at",
            "reason_code",
            "revoked_at",
            "source_version",
            "target_id",
            "target_type",
            "tenant_id",
        },
        context="revocation_marker",
    )
    expires_raw = _optional_str(payload, "expires_at")
    source_raw = payload["source_version"]
    if source_raw is not None and (isinstance(source_raw, bool) or not isinstance(source_raw, int)):
        raise OperationalSerializationError(
            "revocation_marker.source_version must be integer or null."
        )
    try:
        return RevocationMarker(
            target_type=RevocationTargetType(_require_str(payload, "target_type")),
            target_id=_require_str(payload, "target_id"),
            revoked_at=_datetime_from_wire(_require_str(payload, "revoked_at")),
            reason_code=_require_str(payload, "reason_code"),
            tenant_id=_optional_entity_id(payload, "tenant_id", TenantId),
            expires_at=None if expires_raw is None else _datetime_from_wire(expires_raw),
            source_version=None if source_raw is None else StateVersion(source_raw),
        )
    except (ValueError, TypeError) as exc:
        raise OperationalSerializationError(
            "Revocation payload contains invalid domain values."
        ) from exc


def _invalidation_to_payload(event: InvalidationEvent) -> dict[str, object]:
    return {
        "event_id": str(event.event_id),
        "kind": event.kind.value,
        "occurred_at": _datetime_to_wire(event.occurred_at),
        "state_version": event.state_version.value,
        "target_id": event.target_id,
        "tenant_id": _id_to_wire(event.tenant_id),
    }


def _invalidation_from_payload(payload: dict[str, object]) -> InvalidationEvent:
    _require_exact_keys(
        payload,
        {"event_id", "kind", "occurred_at", "state_version", "target_id", "tenant_id"},
        context="invalidation_event",
    )
    try:
        return InvalidationEvent(
            event_id=UUID(_require_str(payload, "event_id")),
            kind=InvalidationKind(_require_str(payload, "kind")),
            target_id=_require_str(payload, "target_id"),
            state_version=StateVersion(_require_int(payload, "state_version")),
            occurred_at=_datetime_from_wire(_require_str(payload, "occurred_at")),
            tenant_id=_optional_entity_id(payload, "tenant_id", TenantId),
        )
    except (ValueError, TypeError) as exc:
        raise OperationalSerializationError(
            "Invalidation payload contains invalid domain values."
        ) from exc


def _datetime_to_wire(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise OperationalSerializationError("Operational timestamps must be UTC-aware.")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _datetime_from_wire(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalSerializationError("Operational timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise OperationalSerializationError("Operational timestamp must be UTC-aware.")
    return parsed.astimezone(UTC)


def _id_to_wire(value: object | None) -> str | None:
    return None if value is None else str(value)


def _optional_entity_id[EntityIdT: EntityId](
    payload: dict[str, object],
    key: str,
    identifier_type: type[EntityIdT],
) -> EntityIdT | None:
    raw = _optional_str(payload, key)
    if raw is None:
        return None
    try:
        return identifier_type.parse(raw)
    except ValueError as exc:
        raise OperationalSerializationError(f"{key} is not a valid identifier.") from exc


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise OperationalSerializationError(f"{context} must be a JSON object.")
    return cast(dict[str, object], value)


def _require_exact_keys(
    payload: dict[str, object],
    expected: set[str],
    *,
    context: str,
) -> None:
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise OperationalSerializationError(
            f"{context} fields mismatch; missing={missing}, extra={extra}."
        )


def _require_str(payload: dict[str, object], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise OperationalSerializationError(f"{key} must be a string.")
    return value


def _optional_str(payload: dict[str, object], key: str) -> str | None:
    value = payload[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise OperationalSerializationError(f"{key} must be a string or null.")
    return value


def _require_int(payload: dict[str, object], key: str) -> int:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperationalSerializationError(f"{key} must be an integer.")
    return value



def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OperationalSerializationError(f"Duplicate JSON field: {key!r}.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise OperationalSerializationError(f"Unsupported JSON constant: {value}.")
