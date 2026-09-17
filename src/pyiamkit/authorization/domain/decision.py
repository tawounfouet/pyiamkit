"""Runtime authorization request and decision value objects."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId, TenantScope

from .binding_value_objects import RoleBindingId
from .value_objects import PermissionCode, RoleId


class AuthorizationResult(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AuthorizationReason(StrEnum):
    ALLOW_ROLE_PERMISSION_MATCH = "ALLOW_ROLE_PERMISSION_MATCH"
    DENY_MEMBERSHIP_NOT_FOUND = "DENY_MEMBERSHIP_NOT_FOUND"
    DENY_NO_ACTIVE_BINDING = "DENY_NO_ACTIVE_BINDING"
    DENY_PERMISSION_NOT_GRANTED = "DENY_PERMISSION_NOT_GRANTED"
    DENY_PERMISSION_NOT_REGISTERED = "DENY_PERMISSION_NOT_REGISTERED"
    DENY_ROLE_TENANT_MISMATCH = "DENY_ROLE_TENANT_MISMATCH"
    DENY_ROLE_UNAVAILABLE = "DENY_ROLE_UNAVAILABLE"
    DENY_SCOPE_MISMATCH = "DENY_SCOPE_MISMATCH"
    DENY_SUBJECT_INACTIVE = "DENY_SUBJECT_INACTIVE"
    DENY_SUBJECT_NOT_FOUND = "DENY_SUBJECT_NOT_FOUND"
    DENY_TENANT_INACTIVE = "DENY_TENANT_INACTIVE"
    DENY_TENANT_NOT_FOUND = "DENY_TENANT_NOT_FOUND"


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Minimal scoped RBAC request for the first runtime authorization engine."""

    subject_id: IdentityId
    tenant_id: TenantId
    permission: PermissionCode
    scope: TenantScope
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if self.scope.tenant_id != self.tenant_id:
            raise ValueError("AuthorizationRequest scope must belong to tenant_id.")


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Deterministic and explainable runtime authorization decision."""

    result: AuthorizationResult
    reason_code: AuthorizationReason
    subject_id: IdentityId
    tenant_id: TenantId
    permission: PermissionCode
    scope: TenantScope
    evaluated_at: datetime
    matched_binding_id: RoleBindingId | None = None
    matched_role_id: RoleId | None = None
    correlation_id: str | None = None
    explanation_path: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.result is AuthorizationResult.ALLOW
