"""Runtime authorization request, decision and explanation value objects."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from pyiamkit.identity import IdentityId
from pyiamkit.shared import EntityId
from pyiamkit.tenancy import TenantId, TenantScope

from .binding_value_objects import RoleBindingId
from .governance import GovernanceRuleId, ResourceDescriptor
from .value_objects import PermissionCode, RoleId


class AuthorizationDecisionId(EntityId):
    """Stable identifier used to correlate a decision with its audit record."""


class AuthorizationResult(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AuthorizationReason(StrEnum):
    ALLOW_INHERITED_ROLE_PERMISSION_MATCH = "ALLOW_INHERITED_ROLE_PERMISSION_MATCH"
    ALLOW_ROLE_PERMISSION_MATCH = "ALLOW_ROLE_PERMISSION_MATCH"
    DENY_CONSTRAINT_CONTEXT_MISSING = "DENY_CONSTRAINT_CONTEXT_MISSING"
    DENY_CONSTRAINT_VIOLATION = "DENY_CONSTRAINT_VIOLATION"
    DENY_MEMBERSHIP_NOT_FOUND = "DENY_MEMBERSHIP_NOT_FOUND"
    DENY_NO_ACTIVE_BINDING = "DENY_NO_ACTIVE_BINDING"
    DENY_PERMISSION_NOT_GRANTED = "DENY_PERMISSION_NOT_GRANTED"
    DENY_PERMISSION_NOT_REGISTERED = "DENY_PERMISSION_NOT_REGISTERED"
    DENY_ROLE_HIERARCHY_INVALID = "DENY_ROLE_HIERARCHY_INVALID"
    DENY_ROLE_TENANT_MISMATCH = "DENY_ROLE_TENANT_MISMATCH"
    DENY_ROLE_UNAVAILABLE = "DENY_ROLE_UNAVAILABLE"
    DENY_SCOPE_MISMATCH = "DENY_SCOPE_MISMATCH"
    DENY_SOD_CONTEXT_MISSING = "DENY_SOD_CONTEXT_MISSING"
    DENY_SOD_DYNAMIC_CONFLICT = "DENY_SOD_DYNAMIC_CONFLICT"
    DENY_SOD_STATIC_CONFLICT = "DENY_SOD_STATIC_CONFLICT"
    DENY_SUBJECT_INACTIVE = "DENY_SUBJECT_INACTIVE"
    DENY_SUBJECT_NOT_FOUND = "DENY_SUBJECT_NOT_FOUND"
    DENY_TENANT_INACTIVE = "DENY_TENANT_INACTIVE"
    DENY_TENANT_NOT_FOUND = "DENY_TENANT_NOT_FOUND"


class ExplanationLevel(StrEnum):
    SUMMARY = "summary"
    DETAILED = "detailed"


@dataclass(frozen=True, slots=True)
class DecisionExplanation:
    decision_id: AuthorizationDecisionId
    allowed: bool
    reason_code: AuthorizationReason
    summary: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Scoped RBAC request with optional protected-resource context."""

    subject_id: IdentityId
    tenant_id: TenantId
    permission: PermissionCode
    scope: TenantScope
    resource: ResourceDescriptor | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if self.scope.tenant_id != self.tenant_id:
            raise ValueError("AuthorizationRequest scope must belong to tenant_id.")
        if self.resource is not None and self.resource.tenant_id != self.tenant_id:
            raise ValueError("AuthorizationRequest resource must belong to tenant_id.")


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Deterministic authorization result with safe and detailed explanation projections."""

    result: AuthorizationResult
    reason_code: AuthorizationReason
    subject_id: IdentityId
    tenant_id: TenantId
    permission: PermissionCode
    scope: TenantScope
    evaluated_at: datetime
    id: AuthorizationDecisionId = field(default_factory=AuthorizationDecisionId.new)
    bound_role_id: RoleId | None = None
    matched_binding_id: RoleBindingId | None = None
    matched_role_id: RoleId | None = None
    matched_rule_id: GovernanceRuleId | None = None
    resource: ResourceDescriptor | None = None
    correlation_id: str | None = None
    explanation_path: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.result is AuthorizationResult.ALLOW

    def explanation(
        self,
        level: ExplanationLevel = ExplanationLevel.SUMMARY,
    ) -> DecisionExplanation:
        summary = "Access allowed." if self.allowed else "Access denied."
        details = self.explanation_path if level is ExplanationLevel.DETAILED else ()
        return DecisionExplanation(
            decision_id=self.id,
            allowed=self.allowed,
            reason_code=self.reason_code,
            summary=summary,
            details=details,
        )
