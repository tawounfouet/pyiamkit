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
from .domain.errors import AuthorizationModelError
from .domain.value_objects import RoleStatus
from .ports import PermissionCatalogRepository, RoleBindingRepository, RoleRepository


class AuthorizationDenied(AuthorizationModelError):
    """Raised by ``require`` when the evaluated request is denied."""

    code = "AUTHORIZATION_DENIED"

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(f"Authorization denied: {decision.reason_code.value}.")


class AuthorizationEngine:
    """Evaluate direct scoped RBAC bindings with explicit default-deny semantics."""

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
    ) -> None:
        self._identities = identity_repository
        self._tenants = tenant_repository
        self._memberships = membership_repository
        self._permissions = permission_repository
        self._roles = role_repository
        self._bindings = binding_repository
        self._clock = clock

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

        resolved = []
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
            resolved.append((binding, role))

        for binding, role in resolved:
            if request.permission in role.permissions:
                return AuthorizationDecision(
                    result=AuthorizationResult.ALLOW,
                    reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
                    subject_id=request.subject_id,
                    tenant_id=request.tenant_id,
                    permission=request.permission,
                    scope=request.scope,
                    evaluated_at=now,
                    matched_binding_id=binding.id,
                    matched_role_id=role.id,
                    correlation_id=request.correlation_id,
                    explanation_path=(
                        f"subject:{request.subject_id}",
                        f"tenant:{request.tenant_id}",
                        f"binding:{binding.id}",
                        f"role:{role.id}",
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

    @staticmethod
    def _deny(
        request: AuthorizationRequest,
        evaluated_at: datetime,
        reason: AuthorizationReason,
        *,
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
            correlation_id=request.correlation_id,
            explanation_path=(
                f"subject:{request.subject_id}",
                f"tenant:{request.tenant_id}",
                *explanation,
                reason.value,
                AuthorizationResult.DENY.value,
            ),
        )
