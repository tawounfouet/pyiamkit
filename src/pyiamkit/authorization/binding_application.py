"""Application orchestration for scoped RoleBindings."""

from datetime import datetime

from pyiamkit.identity import IdentityId, IdentityNotFound, IdentityRepository, IdentityStatus
from pyiamkit.shared import Clock, DomainEventSink
from pyiamkit.tenancy import (
    MembershipRepository,
    TenantId,
    TenantInactive,
    TenantMismatch,
    TenantNotFound,
    TenantRepository,
    TenantScope,
    TenantStatus,
)

from .domain.binding_value_objects import GrantSource, RoleBindingId
from .domain.errors import (
    InvalidRoleBinding,
    RoleBindingAlreadyExists,
    RoleBindingNotFound,
    RoleInactive,
    RoleNotAssignable,
    RoleNotFound,
    RoleTenantMismatch,
)
from .domain.role_binding import RoleBinding
from .domain.value_objects import RoleId, RoleStatus
from .governance import StaticSoDEvaluator
from .ports import RoleBindingRepository, RoleRepository, SoDRuleRepository


class RoleBindingApplicationService:
    """Creates and manages scoped role assignments."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        tenant_repository: TenantRepository,
        membership_repository: MembershipRepository,
        role_repository: RoleRepository,
        binding_repository: RoleBindingRepository,
        clock: Clock,
        event_sink: DomainEventSink,
        sod_repository: SoDRuleRepository | None = None,
        max_hierarchy_depth: int = 32,
    ) -> None:
        self._identities = identity_repository
        self._tenants = tenant_repository
        self._memberships = membership_repository
        self._roles = role_repository
        self._bindings = binding_repository
        self._clock = clock
        self._events = event_sink
        self._static_sod = (
            None
            if sod_repository is None
            else StaticSoDEvaluator(
                role_repository=role_repository,
                sod_repository=sod_repository,
                max_hierarchy_depth=max_hierarchy_depth,
            )
        )

    def assign_role(
        self,
        *,
        identity_id: IdentityId,
        role_id: RoleId,
        tenant_id: TenantId,
        scope: TenantScope,
        valid_until: datetime | None = None,
        grant_source: GrantSource = GrantSource.DIRECT,
        granted_by: IdentityId | None = None,
        justification: str | None = None,
    ) -> RoleBinding:
        now = self._clock.now()
        identity = self._identities.get(identity_id)
        if identity is None:
            raise IdentityNotFound(identity_id)
        if identity.status is not IdentityStatus.ACTIVE:
            raise InvalidRoleBinding("Role assignment requires an active identity.")

        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            raise TenantNotFound(tenant_id)
        if tenant.status is not TenantStatus.ACTIVE:
            raise TenantInactive("Role assignment requires an active tenant.")
        if scope.tenant_id != tenant_id:
            raise TenantMismatch(tenant_id, scope.tenant_id)
        if self._memberships.find_active(identity_id, tenant_id, now) is None:
            raise InvalidRoleBinding("Role assignment requires an active Membership.")

        role = self._roles.get(role_id)
        if role is None:
            raise RoleNotFound(role_id)
        if role.status is not RoleStatus.ACTIVE:
            raise RoleInactive(role_id)
        if not role.assignable:
            raise RoleNotAssignable(role_id)
        if role.tenant_id is not None and role.tenant_id != tenant_id:
            raise RoleTenantMismatch(role.tenant_id, tenant_id)

        active_bindings = self._bindings.find_active_for_subject(identity_id, tenant_id, now)
        for binding in active_bindings:
            if binding.role_id == role_id and binding.scope == scope:
                raise RoleBindingAlreadyExists()
        if self._static_sod is not None:
            self._static_sod.ensure_assignment_allowed(
                candidate_role_id=role_id,
                existing_bindings=active_bindings,
                tenant_id=tenant_id,
            )

        binding = RoleBinding.create(
            identity_id=identity_id,
            role_id=role_id,
            tenant_id=tenant_id,
            scope=scope,
            created_at=now,
            valid_until=valid_until,
            grant_source=grant_source,
            granted_by=granted_by,
            justification=justification,
        )
        return self._save(binding)

    def suspend_binding(self, binding_id: RoleBindingId) -> RoleBinding:
        binding = self._require_binding(binding_id)
        binding.suspend(at=self._clock.now())
        return self._save(binding)

    def reactivate_binding(self, binding_id: RoleBindingId) -> RoleBinding:
        binding = self._require_binding(binding_id)
        binding.reactivate(at=self._clock.now())
        return self._save(binding)

    def revoke_binding(self, binding_id: RoleBindingId) -> RoleBinding:
        binding = self._require_binding(binding_id)
        binding.revoke(at=self._clock.now())
        return self._save(binding)

    def active_bindings(
        self, *, identity_id: IdentityId, tenant_id: TenantId
    ) -> tuple[RoleBinding, ...]:
        return self._bindings.find_active_for_subject(identity_id, tenant_id, self._clock.now())

    def _require_binding(self, binding_id: RoleBindingId) -> RoleBinding:
        binding = self._bindings.get(binding_id)
        if binding is None:
            raise RoleBindingNotFound(binding_id)
        return binding

    def _save(self, binding: RoleBinding) -> RoleBinding:
        events = binding.pull_events()
        self._bindings.save(binding)
        self._events.publish(events)
        saved = self._bindings.get(binding.id)
        if saved is None:
            raise RuntimeError("RoleBinding repository did not return the persisted aggregate.")
        return saved
