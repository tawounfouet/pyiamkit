from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity, IdentityId
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.operations import (
    AuthorizationCacheKey,
    AuthorizationRuntimeUnavailable,
    CacheNamespace,
    DistributedAuthorizationRuntime,
    RedisKeyspace,
    RevocationMarker,
    RevocationTargetType,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters import (
    InMemoryAuthorizationCache,
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantId, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 10, 2, 7, 30, tzinfo=UTC)
PERMISSION = PermissionCode("invoice.read")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


class CountingEngine(AuthorizationEngine):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.calls = 0

    def authorize(self, request: AuthorizationRequest):
        self.calls += 1
        return super().authorize(request)


class AlwaysChangingStateReader:
    def __init__(self) -> None:
        self.calls = 0

    def stamp_for(self, *, identity_id: IdentityId, tenant_id: TenantId) -> SecurityStateStamp:
        del identity_id, tenant_id
        self.calls += 1
        zero = StateVersion(0)
        return SecurityStateStamp(
            runtime_generation=zero,
            identity=StateVersion(self.calls),
            tenant=zero,
            membership=zero,
            subject_authorization=zero,
            tenant_authorization=zero,
            global_authorization=zero,
            governance=zero,
            authentication=zero,
        )


class RevokingEngine(CountingEngine):
    def __init__(
        self,
        *,
        revocations: InMemoryRevocationRegistry,
        security_state: InMemorySecurityStateStore,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._revocations = revocations
        self._security_state = security_state

    def authorize(self, request: AuthorizationRequest):
        decision = super().authorize(request)
        if decision.allowed and decision.matched_binding_id is not None:
            stamp = self._security_state.stamp_for(
                identity_id=request.subject_id,
                tenant_id=request.tenant_id,
            )
            self._revocations.record(
                RevocationMarker(
                    target_type=RevocationTargetType.ROLE_BINDING,
                    target_id=str(decision.matched_binding_id),
                    revoked_at=NOW,
                    reason_code="concurrent_revoke",
                    tenant_id=request.tenant_id,
                    source_version=stamp.subject_authorization,
                )
            )
        return decision


def _setup():
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    clock = FrozenClock()

    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identities.save(identity)

    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    tenant.pull_events()
    tenant.activate(at=NOW)
    tenant.pull_events()
    tenants.save(tenant)

    membership = Membership.create(
        identity_id=identity.id,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    membership.pull_events()
    membership.activate(at=NOW)
    membership.pull_events()
    memberships.save(membership)

    permissions.save(Permission(PERMISSION, "Read invoices"))
    role = Role.create(
        name="Reader",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    role.add_permission(PERMISSION, at=NOW)
    role.pull_events()
    roles.save(role)

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
    )
    binding.pull_events()
    bindings.save(binding)

    engine = CountingEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        clock=clock,
    )
    state = InMemorySecurityStateStore()
    cache = InMemoryAuthorizationCache()
    revocations = InMemoryRevocationRegistry()
    runtime = DistributedAuthorizationRuntime(
        engine=engine,
        security_state=state,
        cache=cache,
        revocations=revocations,
        clock=clock,
    )
    request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=PERMISSION,
        scope=TenantScope(tenant.id),
        correlation_id="security-test",
    )
    return {
        "runtime": runtime,
        "engine": engine,
        "state": state,
        "cache": cache,
        "revocations": revocations,
        "request": request,
        "role": role,
        "roles": roles,
        "clock": clock,
        "repositories": {
            "identities": identities,
            "tenants": tenants,
            "memberships": memberships,
            "permissions": permissions,
            "bindings": bindings,
        },
    }


@pytest.mark.security
def test_authorization_cache_key_is_partitioned_by_tenant() -> None:
    subject_id = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()
    request_a = AuthorizationRequest(
        subject_id=subject_id,
        tenant_id=tenant_a,
        permission=PERMISSION,
        scope=TenantScope(tenant_a),
    )
    request_b = AuthorizationRequest(
        subject_id=subject_id,
        tenant_id=tenant_b,
        permission=PERMISSION,
        scope=TenantScope(tenant_b),
    )

    assert AuthorizationCacheKey.from_request(request_a) != AuthorizationCacheKey.from_request(
        request_b
    )


@pytest.mark.security
def test_security_state_subject_tenant_dimensions_do_not_cross_tenants() -> None:
    store = InMemorySecurityStateStore()
    identity_id = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    store.bump_membership(identity_id, tenant_a)
    store.bump_subject_authorization(identity_id, tenant_a)
    store.bump_tenant_authorization(tenant_a)
    store.bump_governance(tenant_a)

    stamp_a = store.stamp_for(identity_id=identity_id, tenant_id=tenant_a)
    stamp_b = store.stamp_for(identity_id=identity_id, tenant_id=tenant_b)

    assert stamp_a.membership == StateVersion(1)
    assert stamp_a.subject_authorization == StateVersion(1)
    assert stamp_a.tenant_authorization == StateVersion(1)
    assert stamp_a.governance == StateVersion(1)
    assert stamp_b.membership == StateVersion(0)
    assert stamp_b.subject_authorization == StateVersion(0)
    assert stamp_b.tenant_authorization == StateVersion(0)
    assert stamp_b.governance == StateVersion(0)


@pytest.mark.security
def test_lost_pubsub_invalidation_cannot_preserve_stale_allow() -> None:
    setup = _setup()
    runtime = setup["runtime"]
    engine = setup["engine"]
    state = setup["state"]
    request = setup["request"]
    role = setup["role"]
    roles = setup["roles"]

    assert runtime.authorize(request).allowed is True
    assert engine.calls == 1

    role.remove_permission(PERMISSION, at=NOW)
    role.pull_events()
    roles.save(role)
    state.bump_tenant_authorization(request.tenant_id)

    decision = runtime.authorize(request)

    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_PERMISSION_NOT_GRANTED
    assert engine.calls == 2


@pytest.mark.security
def test_revocation_arriving_during_authoritative_evaluation_overrides_allow() -> None:
    setup = _setup()
    request = setup["request"]
    state = setup["state"]
    revocations = setup["revocations"]
    clock = setup["clock"]
    repositories = setup["repositories"]

    engine = RevokingEngine(
        revocations=revocations,
        security_state=state,
        identity_repository=repositories["identities"],
        tenant_repository=repositories["tenants"],
        membership_repository=repositories["memberships"],
        permission_repository=repositories["permissions"],
        role_repository=setup["roles"],
        binding_repository=repositories["bindings"],
        clock=clock,
    )
    runtime = DistributedAuthorizationRuntime(
        engine=engine,
        security_state=state,
        cache=InMemoryAuthorizationCache(),
        revocations=revocations,
        clock=clock,
    )

    decision = runtime.authorize(request)

    assert decision.allowed is False
    assert decision.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING
    assert engine.calls == 1


@pytest.mark.security
def test_permanently_unstable_security_state_never_returns_allow() -> None:
    setup = _setup()
    runtime = DistributedAuthorizationRuntime(
        engine=setup["engine"],
        security_state=AlwaysChangingStateReader(),
        cache=InMemoryAuthorizationCache(),
        revocations=setup["revocations"],
        clock=setup["clock"],
        max_state_retries=1,
    )

    with pytest.raises(AuthorizationRuntimeUnavailable):
        runtime.authorize(setup["request"])


@pytest.mark.security
def test_redis_namespaces_isolate_environment_and_schema_generation() -> None:
    key = AuthorizationCacheKey("a" * 64)
    production_v1 = RedisKeyspace(CacheNamespace("billing", "prod", schema_version=1))
    production_v2 = RedisKeyspace(CacheNamespace("billing", "prod", schema_version=2))
    staging_v1 = RedisKeyspace(CacheNamespace("billing", "staging", schema_version=1))

    keys = {
        production_v1.authorization_cache(key),
        production_v2.authorization_cache(key),
        staging_v1.authorization_cache(key),
    }

    assert len(keys) == 3
