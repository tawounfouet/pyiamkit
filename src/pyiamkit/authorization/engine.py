"""Default-deny runtime authorization engine."""

from datetime import datetime

from pyiamkit.identity import IdentityRepository, IdentityStatus
from pyiamkit.shared import Clock
from pyiamkit.tenancy import MembershipRepository, TenantRepository, TenantStatus

from .domain.decision import (
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationRequest,
    AuthorizationResult,
)
from .domain.errors import AuthorizationModelError, RoleHierarchyError
from .domain.governance import GovernanceRuleId, GovernanceViolation, GovernanceViolationKind
from .domain.role_binding import RoleBinding
from .domain.value_objects import RoleStatus
from .governance import ConstraintEvaluator, DynamicSoDEvaluator, StaticSoDEvaluator
from .hierarchy import RoleHierarchyResolver
from .ports import (
    ConstraintRepository,
    PermissionCatalogRepository,
    RoleBindingRepository,
    RoleRepository,
    SoDRuleRepository,
)


class AuthorizationDenied(AuthorizationModelError):
    """Raised by ``require`` when the evaluated request is denied."""

    code = "AUTHORIZATION_DENIED"

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(f"Authorization denied: {decision.reason_code.value}.")


class AuthorizationEngine:
    """Evaluate RBAC, hierarchy, constraints and Separation of Duties."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        tenant_repository: TenantRepository,
        membership_repository: MembershipRepository,
        permission_repository: PermissionCatalogRepository,
        role_repository: RoleRepository,
        binding_repository: RoleBindingRepository,
        clock: Clock,
        constraint_repository: ConstraintRepository | None = None,
        sod_repository: SoDRuleRepository | None = None,
        max_hierarchy_depth: int = 32,
    ) -> None:
        self._identities = identity_repository
        self._tenants = tenant_repository
        self._memberships = membership_repository
        self._permissions = permission_repository
        self._roles = role_repository
        self._bindings = binding_repository
        self._clock = clock
        self._hierarchy = RoleHierarchyResolver(
            role_repository,
            max_depth=max_hierarchy_depth,
        )
        self._constraints = (
            None if constraint_repository is None else ConstraintEvaluator(constraint_repository)
        )
        self._dynamic_sod = None if sod_repository is None else DynamicSoDEvaluator(sod_repository)
        self._static_sod = (
            None
            if sod_repository is None
            else StaticSoDEvaluator(
                role_repository=role_repository,
                sod_repository=sod_repository,
                max_hierarchy_depth=max_hierarchy_depth,
            )
        )

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        now = self._clock.now()

        identity = self._identities.get(request.subject_id)
        if identity is None:
            return self._deny(request, now, AuthorizationReason.DENY_SUBJECT_NOT_FOUND)
        if identity.status is not IdentityStatus.ACTIVE:
            return self._deny(request, now, AuthorizationReason.DENY_SUBJECT_INACTIVE)

        tenant = self._tenants.get(request.tenant_id)
        if tenant is None:
            return self._deny(request, now, AuthorizationReason.DENY_TENANT_NOT_FOUND)
        if tenant.status is not TenantStatus.ACTIVE:
            return self._deny(request, now, AuthorizationReason.DENY_TENANT_INACTIVE)

        membership = self._memberships.find_active(request.subject_id, request.tenant_id, now)
        if membership is None:
            return self._deny(request, now, AuthorizationReason.DENY_MEMBERSHIP_NOT_FOUND)

        if self._permissions.get(request.permission) is None:
            return self._deny(request, now, AuthorizationReason.DENY_PERMISSION_NOT_REGISTERED)

        bindings = self._bindings.find_active_for_subject(
            request.subject_id,
            request.tenant_id,
            now,
        )
        if not bindings:
            return self._deny(request, now, AuthorizationReason.DENY_NO_ACTIVE_BINDING)

        scoped_bindings = tuple(binding for binding in bindings if binding.scope == request.scope)
        if not scoped_bindings:
            return self._deny(request, now, AuthorizationReason.DENY_SCOPE_MISMATCH)

        for binding in sorted(scoped_bindings, key=lambda item: str(item.id)):
            role = self._roles.get(binding.role_id)
            if role is None or role.status is not RoleStatus.ACTIVE:
                return self._deny(
                    request,
                    now,
                    AuthorizationReason.DENY_ROLE_UNAVAILABLE,
                    explanation=(f"binding:{binding.id}",),
                )
            if role.tenant_id is not None and role.tenant_id != request.tenant_id:
                return self._deny(
                    request,
                    now,
                    AuthorizationReason.DENY_ROLE_TENANT_MISMATCH,
                    explanation=(f"binding:{binding.id}", f"role:{role.id}"),
                )
            try:
                path = self._hierarchy.permission_path(role.id, request.permission)
            except RoleHierarchyError as exc:
                return self._deny(
                    request,
                    now,
                    AuthorizationReason.DENY_ROLE_HIERARCHY_INVALID,
                    explanation=(
                        f"binding:{binding.id}",
                        f"role:{role.id}",
                        f"hierarchy_error:{exc.code}",
                    ),
                )
            if path is None:
                continue

            violation = self._evaluate_governance(request, bindings)
            if violation is not None:
                return self._deny(
                    request,
                    now,
                    self._reason_for_violation(violation),
                    matched_rule_id=violation.rule_id,
                    explanation=(
                        f"binding:{binding.id}",
                        f"role:{role.id}",
                        f"rule:{violation.rule_id}",
                        f"governance:{violation.kind.value}",
                    ),
                )

            source = path[-1]
            inherited = len(path) > 1
            return AuthorizationDecision(
                result=AuthorizationResult.ALLOW,
                reason_code=(
                    AuthorizationReason.ALLOW_INHERITED_ROLE_PERMISSION_MATCH
                    if inherited
                    else AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH
                ),
                subject_id=request.subject_id,
                tenant_id=request.tenant_id,
                permission=request.permission,
                scope=request.scope,
                evaluated_at=now,
                bound_role_id=role.id,
                matched_binding_id=binding.id,
                matched_role_id=source.id,
                resource=request.resource,
                correlation_id=request.correlation_id,
                explanation_path=(
                    f"subject:{request.subject_id}",
                    f"tenant:{request.tenant_id}",
                    f"binding:{binding.id}",
                    *(f"role:{item.id}" for item in path),
                    f"permission:{request.permission}",
                    AuthorizationResult.ALLOW.value,
                ),
            )

        return self._deny(request, now, AuthorizationReason.DENY_PERMISSION_NOT_GRANTED)

    def can(self, request: AuthorizationRequest) -> bool:
        return self.authorize(request).allowed

    def require(self, request: AuthorizationRequest) -> AuthorizationDecision:
        decision = self.authorize(request)
        if not decision.allowed:
            raise AuthorizationDenied(decision)
        return decision

    def explain(self, request: AuthorizationRequest) -> AuthorizationDecision:
        return self.authorize(request)

    def _evaluate_governance(
        self,
        request: AuthorizationRequest,
        bindings: tuple[RoleBinding, ...],
    ) -> GovernanceViolation | None:
        if self._static_sod is not None:
            violation = self._static_sod.detect_runtime(
                bindings=bindings,
                tenant_id=request.tenant_id,
            )
            if violation is not None:
                return violation
        if self._dynamic_sod is not None:
            violation = self._dynamic_sod.evaluate(request)
            if violation is not None:
                return violation
        if self._constraints is not None:
            return self._constraints.evaluate(request)
        return None

    @staticmethod
    def _reason_for_violation(violation: GovernanceViolation) -> AuthorizationReason:
        mapping: dict[GovernanceViolationKind, AuthorizationReason] = {
            GovernanceViolationKind.CONSTRAINT_CONTEXT_MISSING: (
                AuthorizationReason.DENY_CONSTRAINT_CONTEXT_MISSING
            ),
            GovernanceViolationKind.CONSTRAINT_VIOLATION: (
                AuthorizationReason.DENY_CONSTRAINT_VIOLATION
            ),
            GovernanceViolationKind.SOD_CONTEXT_MISSING: (
                AuthorizationReason.DENY_SOD_CONTEXT_MISSING
            ),
            GovernanceViolationKind.SOD_DYNAMIC_CONFLICT: (
                AuthorizationReason.DENY_SOD_DYNAMIC_CONFLICT
            ),
            GovernanceViolationKind.SOD_STATIC_CONFLICT: (
                AuthorizationReason.DENY_SOD_STATIC_CONFLICT
            ),
        }
        return mapping[violation.kind]

    @staticmethod
    def _deny(
        request: AuthorizationRequest,
        evaluated_at: datetime,
        reason: AuthorizationReason,
        *,
        matched_rule_id: GovernanceRuleId | None = None,
        explanation: tuple[str, ...] = (),
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            result=AuthorizationResult.DENY,
            reason_code=reason,
            subject_id=request.subject_id,
            tenant_id=request.tenant_id,
            permission=request.permission,
            scope=request.scope,
            evaluated_at=evaluated_at,
            matched_rule_id=matched_rule_id,
            resource=request.resource,
            correlation_id=request.correlation_id,
            explanation_path=(
                f"subject:{request.subject_id}",
                f"tenant:{request.tenant_id}",
                *explanation,
                reason.value,
                AuthorizationResult.DENY.value,
            ),
        )
