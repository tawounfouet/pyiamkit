"""Authorization-cache value objects and deterministic request keys."""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationRequest,
    AuthorizationResult,
    GovernanceRuleId,
    RoleBindingId,
    RoleId,
)

from .state import SecurityStateStamp

_NAMESPACE_PART_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

type _CanonicalScalar = bool | int | str | None
type _CanonicalValue = _CanonicalScalar | list["_CanonicalValue"] | dict[str, "_CanonicalValue"]
type _CanonicalMapping = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CacheNamespace:
    """Canonical namespace isolating operational data between applications."""

    application: str
    environment: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        application = self._normalize_part(self.application, field_name="application")
        environment = self._normalize_part(self.environment, field_name="environment")
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("CacheNamespace.schema_version must be an integer")
        if self.schema_version < 1:
            raise ValueError("CacheNamespace.schema_version must be greater than or equal to one")
        object.__setattr__(self, "application", application)
        object.__setattr__(self, "environment", environment)

    @property
    def prefix(self) -> str:
        """Return the canonical namespace prefix used by operational adapters."""

        return f"pyiamkit:{self.application}:{self.environment}:v{self.schema_version}"

    @staticmethod
    def _normalize_part(value: str, *, field_name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"CacheNamespace.{field_name} must be a string")
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError(f"CacheNamespace.{field_name} must not be empty")
        if not _NAMESPACE_PART_PATTERN.fullmatch(normalized):
            raise ValueError(f"CacheNamespace.{field_name} contains unsupported characters")
        return normalized


@dataclass(frozen=True, slots=True)
class AuthorizationCacheKey:
    """Opaque SHA-256 digest of authorization facts relevant to the decision."""

    digest: str

    def __post_init__(self) -> None:
        normalized = self.digest.strip().lower()
        if not _SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("AuthorizationCacheKey.digest must be a lowercase SHA-256 hex digest")
        object.__setattr__(self, "digest", normalized)

    @classmethod
    def from_request(cls, request: AuthorizationRequest) -> "AuthorizationCacheKey":
        """Derive a deterministic key while deliberately excluding correlation_id."""

        resource: dict[str, _CanonicalValue] | None = None
        if request.resource is not None:
            resource = {
                "resource_type": request.resource.resource_type,
                "resource_id": request.resource.resource_id,
                "tenant_id": str(request.resource.tenant_id),
                "owner_id": (
                    None
                    if request.resource.owner_id is None
                    else str(request.resource.owner_id)
                ),
                "attributes": _canonicalize_mapping(request.resource.attributes),
            }

        authentication: dict[str, _CanonicalValue] | None = None
        if request.authentication is not None:
            authentication = {
                "assurance_level": request.authentication.assurance_level.value,
                "mfa": request.authentication.mfa,
                "authenticated_at": _canonical_datetime(request.authentication.authenticated_at),
            }

        payload: dict[str, _CanonicalValue] = {
            "schema_version": 1,
            "subject_id": str(request.subject_id),
            "tenant_id": str(request.tenant_id),
            "permission": str(request.permission),
            "scope_tenant_id": str(request.scope.tenant_id),
            "resource": resource,
            "authentication": authentication,
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return cls(hashlib.sha256(canonical).hexdigest())

    def __str__(self) -> str:
        return self.digest


@dataclass(frozen=True, slots=True)
class CachedAuthorizationDecision:
    """Cache-safe semantic projection of an AuthorizationDecision."""

    result: AuthorizationResult
    reason_code: AuthorizationReason
    bound_role_id: RoleId | None = None
    matched_binding_id: RoleBindingId | None = None
    matched_role_id: RoleId | None = None
    matched_rule_id: GovernanceRuleId | None = None
    required_assurance_level: AssuranceLevel | None = None
    required_mfa: bool | None = None
    explanation_path: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.result is AuthorizationResult.ALLOW

    @classmethod
    def from_decision(cls, decision: AuthorizationDecision) -> "CachedAuthorizationDecision":
        return cls(
            result=decision.result,
            reason_code=decision.reason_code,
            bound_role_id=decision.bound_role_id,
            matched_binding_id=decision.matched_binding_id,
            matched_role_id=decision.matched_role_id,
            matched_rule_id=decision.matched_rule_id,
            required_assurance_level=decision.required_assurance_level,
            required_mfa=decision.required_mfa,
            explanation_path=decision.explanation_path,
        )

    def to_decision(
        self,
        request: AuthorizationRequest,
        *,
        evaluated_at: datetime,
    ) -> AuthorizationDecision:
        """Rehydrate a fresh decision identity and request correlation context."""

        _require_utc(evaluated_at, field_name="evaluated_at")
        return AuthorizationDecision(
            result=self.result,
            reason_code=self.reason_code,
            subject_id=request.subject_id,
            tenant_id=request.tenant_id,
            permission=request.permission,
            scope=request.scope,
            evaluated_at=evaluated_at,
            bound_role_id=self.bound_role_id,
            matched_binding_id=self.matched_binding_id,
            matched_role_id=self.matched_role_id,
            matched_rule_id=self.matched_rule_id,
            required_assurance_level=self.required_assurance_level,
            required_mfa=self.required_mfa,
            resource=request.resource,
            correlation_id=request.correlation_id,
            explanation_path=self.explanation_path,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationCacheEntry:
    """One bounded authorization-cache entry tied to an exact security-state stamp."""

    key: AuthorizationCacheKey
    decision: CachedAuthorizationDecision
    state_stamp: SecurityStateStamp
    cached_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_utc(self.cached_at, field_name="cached_at")
        _require_utc(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.cached_at:
            raise ValueError("AuthorizationCacheEntry.expires_at must be after cached_at")

    def is_valid_for(self, state_stamp: SecurityStateStamp, *, at: datetime) -> bool:
        _require_utc(at, field_name="at")
        return self.state_stamp == state_stamp and at < self.expires_at


def _canonicalize_mapping(value: _CanonicalMapping) -> dict[str, _CanonicalValue]:
    canonical: dict[str, _CanonicalValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("Authorization cache resource attribute keys must be strings")
        canonical[key] = _canonicalize_value(item)
    return canonical


def _canonicalize_value(value: object) -> _CanonicalValue:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Authorization cache resource floats must be finite")
        return {"$float": format(value, ".17g")}
    if isinstance(value, Decimal):
        return {"$decimal": str(value.normalize())}
    if isinstance(value, UUID):
        return {"$uuid": str(value)}
    if isinstance(value, datetime):
        return {"$datetime": _canonical_datetime(value)}
    if isinstance(value, Mapping):
        return _canonicalize_mapping(value)
    if isinstance(value, list | tuple):
        return [_canonicalize_value(item) for item in value]
    if isinstance(value, set | frozenset):
        normalized = [_canonicalize_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, separators=(",", ":"), sort_keys=True),
        )
    raise TypeError(
        "Authorization cache resource attributes must use deterministic JSON-compatible values"
    )


def _canonical_datetime(value: datetime) -> str:
    _require_utc(value, field_name="datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_utc(value: datetime, *, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field_name} must be UTC-aware")
