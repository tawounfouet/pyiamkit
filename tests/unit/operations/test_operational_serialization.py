import json
from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthorizationReason,
    AuthorizationResult,
    GovernanceRuleId,
    RoleBindingId,
    RoleId,
)
from pyiamkit.operations import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    InvalidationEvent,
    InvalidationKind,
    OperationalJsonCodec,
    OperationalSerializationError,
    RevocationMarker,
    RevocationTargetType,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.tenancy import MembershipId, TenantId

NOW = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)


def _stamp() -> SecurityStateStamp:
    return SecurityStateStamp(
        runtime_generation=StateVersion(1),
        identity=StateVersion(2),
        tenant=StateVersion(3),
        membership=StateVersion(4),
        subject_authorization=StateVersion(5),
        tenant_authorization=StateVersion(6),
        global_authorization=StateVersion(7),
        governance=StateVersion(8),
        authentication=StateVersion(9),
    )


def _cache_entry() -> AuthorizationCacheEntry:
    return AuthorizationCacheEntry(
        key=AuthorizationCacheKey("a" * 64),
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.ALLOW,
            reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
            valid_until=NOW + timedelta(seconds=20),
            matched_membership_id=MembershipId.new(),
            bound_role_id=RoleId.new(),
            matched_binding_id=RoleBindingId.new(),
            matched_role_id=RoleId.new(),
            matched_rule_id=GovernanceRuleId.new(),
            required_assurance_level=AssuranceLevel.AAL2,
            required_mfa=True,
            explanation_path=("role:reader", "permission:invoice.read", "allow"),
        ),
        state_stamp=_stamp(),
        cached_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )


def test_security_state_round_trip_is_canonical_and_deterministic() -> None:
    codec = OperationalJsonCodec()
    stamp = _stamp()

    first = codec.encode_security_state(stamp)
    second = codec.encode_security_state(stamp)

    assert first == second
    assert first.startswith(b"{")
    assert b"pickle" not in first.lower()
    assert codec.decode_security_state(first) == stamp


def test_authorization_cache_entry_round_trip_preserves_semantics() -> None:
    codec = OperationalJsonCodec()
    entry = _cache_entry()

    encoded = codec.encode_authorization_cache_entry(entry)
    decoded = codec.decode_authorization_cache_entry(encoded)

    assert decoded == entry


def test_revocation_marker_round_trip_preserves_version_and_tenant() -> None:
    codec = OperationalJsonCodec()
    tenant_id = TenantId.new()
    marker = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-42",
        revoked_at=NOW,
        reason_code="suspended",
        tenant_id=tenant_id,
        expires_at=NOW + timedelta(minutes=5),
        source_version=StateVersion(4),
    )

    decoded = codec.decode_revocation_marker(codec.encode_revocation_marker(marker))

    assert decoded == marker


def test_invalidation_event_round_trip_preserves_event_identity() -> None:
    codec = OperationalJsonCodec()
    event = InvalidationEvent(
        kind=InvalidationKind.AUTHORIZATION,
        target_id="subject-tenant-42",
        state_version=StateVersion(8),
        occurred_at=NOW,
        tenant_id=TenantId.new(),
    )

    decoded = codec.decode_invalidation_event(codec.encode_invalidation_event(event))

    assert decoded == event
    assert decoded.event_id == event.event_id


def test_codec_rejects_wrong_schema_version() -> None:
    codec = OperationalJsonCodec()
    raw = json.loads(codec.encode_security_state(_stamp()))
    raw["schema_version"] = 2

    with pytest.raises(OperationalSerializationError, match="schema_version"):
        codec.decode_security_state(json.dumps(raw).encode())


def test_codec_rejects_wrong_payload_type() -> None:
    codec = OperationalJsonCodec()
    raw = json.loads(codec.encode_security_state(_stamp()))
    raw["payload_type"] = "revocation_marker"

    with pytest.raises(OperationalSerializationError, match="payload_type"):
        codec.decode_security_state(json.dumps(raw).encode())


def test_codec_rejects_extra_or_missing_fields() -> None:
    codec = OperationalJsonCodec()
    raw = json.loads(codec.encode_security_state(_stamp()))
    raw["payload"]["unexpected"] = "value"

    with pytest.raises(OperationalSerializationError, match="fields mismatch"):
        codec.decode_security_state(json.dumps(raw).encode())

    del raw["payload"]["unexpected"]
    del raw["payload"]["identity"]
    with pytest.raises(OperationalSerializationError, match="fields mismatch"):
        codec.decode_security_state(json.dumps(raw).encode())


def test_codec_rejects_negative_security_state_version() -> None:
    codec = OperationalJsonCodec()
    raw = json.loads(codec.encode_security_state(_stamp()))
    raw["payload"]["identity"] = -1

    with pytest.raises(OperationalSerializationError, match="invalid domain values"):
        codec.decode_security_state(json.dumps(raw).encode())


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"\xff",
        b'{"schema_version":1,"schema_version":1,"payload_type":"x","payload":{}}',
        b'{"schema_version":1,"payload_type":"x","payload":{"value":NaN}}',
    ],
)
def test_codec_rejects_malformed_or_ambiguous_json(payload: bytes) -> None:
    codec = OperationalJsonCodec()

    with pytest.raises(OperationalSerializationError):
        codec.decode_security_state(payload)


def test_cache_decoder_rejects_unknown_enum_and_unknown_nested_field() -> None:
    codec = OperationalJsonCodec()
    raw = json.loads(codec.encode_authorization_cache_entry(_cache_entry()))
    raw["payload"]["decision"]["result"] = "maybe"

    with pytest.raises(OperationalSerializationError, match="invalid domain values"):
        codec.decode_authorization_cache_entry(json.dumps(raw).encode())

    raw = json.loads(codec.encode_authorization_cache_entry(_cache_entry()))
    raw["payload"]["decision"]["unknown"] = True

    with pytest.raises(OperationalSerializationError, match="fields mismatch"):
        codec.decode_authorization_cache_entry(json.dumps(raw).encode())


def test_revocation_decoder_rejects_invalid_target_type() -> None:
    codec = OperationalJsonCodec()
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-42",
        revoked_at=NOW,
        reason_code="logout",
    )
    raw = json.loads(codec.encode_revocation_marker(marker))
    raw["payload"]["target_type"] = "unknown"

    with pytest.raises(OperationalSerializationError, match="invalid domain values"):
        codec.decode_revocation_marker(json.dumps(raw).encode())


def test_invalidation_event_validates_target_and_utc_time() -> None:
    with pytest.raises(ValueError, match="target_id must not be empty"):
        InvalidationEvent(
            kind=InvalidationKind.IDENTITY,
            target_id=" ",
            state_version=StateVersion(1),
            occurred_at=NOW,
        )

    with pytest.raises(ValueError, match="UTC-aware"):
        InvalidationEvent(
            kind=InvalidationKind.IDENTITY,
            target_id="identity-1",
            state_version=StateVersion(1),
            occurred_at=NOW.replace(tzinfo=None),
        )
