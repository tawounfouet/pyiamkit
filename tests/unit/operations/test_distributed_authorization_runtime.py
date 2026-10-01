from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from redis.exceptions import RedisError

from pyiamkit.audit.adapters import InMemoryAuditRepository
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
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.operations import (
    AuthorizationRuntimeUnavailable,
    CacheNamespace,
    DistributedAuthorizationRuntime,
    RevocationMarker,
    RedisKeyspace,
    RevocationTargetType,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters import (
    InMemoryAuthorizationCache,
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)
from pyiamkit.operations.adapters.redis import RedisAuthorizationCache
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository
from pyiamkit.tenancy.domain.membership import Membership
from pyiamkit.tenancy.domain.tenant import Tenant

NOW = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
PERMISSION = PermissionCode("invoice.read")


class FailingRedisClient:
    def get(self, name: str) -> bytes | str | None:
        del name
        raise RedisError("redis unavailable")

    def set(
        self,
        name: str,
        value: bytes,
        *,
        pxat: int,
    ) -> object:
        del name, value, pxat
        raise RedisError("redis unavailable")

    def delete(self, *names: str | bytes) -> object:
        del names
        raise RedisError("redis unavailable")

    def scan_iter(
        self,
        *,
        match: str,
        count: int,
    ) -> Iterator[str | bytes]:
        del match, count
        raise RedisError("redis unavailable")
        yield


class MutableClock(Clock):
    def __init__(self, current: datetime = NOW) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


class CountingAuthorizationEngine(AuthorizationEngine):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.calls = 0

    def authorize(self, request: AuthorizationRequest):
        self.calls += 1
        return super().authorize(request)


class OneChangeStateReader:
    def __init__(self) -> None:
        self.calls = 0

    def stamp_for(self, *, identity_id: object, tenant_id: object) -> SecurityStateStamp:
        self.calls += 1
        version = StateVersion(0 if self.calls == 1 else 1)
        return _stamp(identity=version)


class AlwaysChangingStateReader:
    def __init__(self) -> None:
        self.calls = 0

    def stamp_for(self, *, identity_id: object, tenant_id: object) -> SecurityStateStamp:
        self.calls += 1
        return _stamp(identity=StateVersion(self.calls))


def _stamp(*, identity: StateVersion | None = None) -> SecurityStateStamp:
    zero = StateVersion(0)
    return SecurityStateStamp(
        runtime_generation=zero,
        identity=zero if identity is None else identity,
        tenant=zero,
        membership=zero,
        subject_authorization=zero,
        tenant_authorization=zero,
        global_authorization=zero,
        governance=zero,
        authentication=zero,
    )


def _setup(
    *,
    binding_valid_until: datetime | None = None,
    audit: InMemoryAuditRepository | None = None,
):
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    clock = MutableClock()

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

    membership = Membership.create(identity_id=identity.id, tenant_id=tenant.id, created_at=NOW)
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
        valid_until=binding_valid_until,
    )
    binding.pull_events()
    bindings.save(binding)

    engine = CountingAuthorizationEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        clock=clock,
        audit_sink=audit,
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
        correlation_id="corr-1",
    )
    return runtime, engine, state, revocations, clock, request, membership, binding


def test_cache_hit_skips_second_authoritative_evaluation() -> None:
    runtime, engine, _, _, _, request, _, _ = _setup()

    first = runtime.authorize(request)
    second = runtime.authorize(request)

    assert first.allowed is True
    assert second.allowed is True
    assert engine.calls == 1
    assert second.id != first.id


def test_cache_hit_rehydrates_current_correlation_and_is_audited() -> None:
    audit = InMemoryAuditRepository()
    runtime, engine, _, _, _, request, _, _ = _setup(audit=audit)
    first = runtime.authorize(request)
    replay = AuthorizationRequest(
        subject_id=request.subject_id,
        tenant_id=request.tenant_id,
        permission=request.permission,
        scope=request.scope,
        correlation_id="corr-2",
    )

    second = runtime.authorize(replay)

    assert engine.calls == 1
    assert second.id != first.id
    assert second.correlation_id == "corr-2"
    assert len(audit.all()) == 2
    assert audit.all()[1].correlation_id == "corr-2"


def test_security_state_change_turns_cached_allow_into_miss() -> None:
    runtime, engine, state, _, _, request, _, _ = _setup()
    assert runtime.authorize(request).allowed is True

    state.bump_identity(request.subject_id)
    second = runtime.authorize(request)

    assert second.allowed is True
    assert engine.calls == 2


def test_identity_revocation_wins_over_cached_allow() -> None:
    runtime, engine, state, revocations, _, request, _, _ = _setup()
    assert runtime.authorize(request).allowed is True
    stamp = state.stamp_for(identity_id=request.subject_id, tenant_id=request.tenant_id)
    revocations.record(
        RevocationMarker(
            target_type=RevocationTargetType.IDENTITY,
            target_id=str(request.subject_id),
            revoked_at=NOW,
            reason_code="security_lock",
            source_version=stamp.identity,
        )
    )

    denied = runtime.authorize(request)

    assert denied.allowed is False
    assert denied.reason_code is AuthorizationReason.DENY_SUBJECT_INACTIVE
    assert engine.calls == 1


def test_role_binding_revocation_wins_over_cached_allow() -> None:
    runtime, engine, state, revocations, _, request, _, binding = _setup()
    first = runtime.authorize(request)
    stamp = state.stamp_for(identity_id=request.subject_id, tenant_id=request.tenant_id)
    revocations.record(
        RevocationMarker(
            target_type=RevocationTargetType.ROLE_BINDING,
            target_id=str(binding.id),
            revoked_at=NOW,
            reason_code="emergency_revoke",
            tenant_id=request.tenant_id,
            source_version=stamp.subject_authorization,
        )
    )

    denied = runtime.authorize(request)

    assert first.matched_binding_id == binding.id
    assert denied.allowed is False
    assert denied.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING
    assert engine.calls == 1


def test_cache_never_outlives_role_binding_validity() -> None:
    valid_until = NOW + timedelta(seconds=5)
    runtime, engine, _, _, clock, request, _, _ = _setup(binding_valid_until=valid_until)
    first = runtime.authorize(request)
    assert first.valid_until == valid_until

    clock.current = valid_until
    second = runtime.authorize(request)

    assert second.allowed is False
    assert second.reason_code is AuthorizationReason.DENY_NO_ACTIVE_BINDING
    assert engine.calls == 2


def test_state_change_during_evaluation_retries_once() -> None:
    _, engine, _, revocations, clock, request, _, _ = _setup()
    retrying = DistributedAuthorizationRuntime(
        engine=engine,
        security_state=OneChangeStateReader(),
        cache=InMemoryAuthorizationCache(),
        revocations=revocations,
        clock=clock,
        max_state_retries=1,
    )

    decision = retrying.authorize(request)

    assert decision.allowed is True
    assert engine.calls == 2


def test_unstable_state_fails_safely_after_bounded_retry() -> None:
    _, engine, _, revocations, clock, request, _, _ = _setup()
    unstable = DistributedAuthorizationRuntime(
        engine=engine,
        security_state=AlwaysChangingStateReader(),
        cache=InMemoryAuthorizationCache(),
        revocations=revocations,
        clock=clock,
        max_state_retries=1,
    )

    with pytest.raises(AuthorizationRuntimeUnavailable):
        unstable.authorize(request)

    assert engine.calls == 2


def test_runtime_validates_retry_and_cache_ttl_configuration() -> None:
    runtime, engine, state, revocations, clock, _, _, _ = _setup()
    assert runtime is not None

    with pytest.raises(ValueError, match="cache_ttl must be positive"):
        DistributedAuthorizationRuntime(
            engine=engine,
            security_state=state,
            cache=InMemoryAuthorizationCache(),
            revocations=revocations,
            clock=clock,
            cache_ttl=timedelta(0),
        )

    with pytest.raises(ValueError, match="greater than or equal to zero"):
        DistributedAuthorizationRuntime(
            engine=engine,
            security_state=state,
            cache=InMemoryAuthorizationCache(),
            revocations=revocations,
            clock=clock,
            max_state_retries=-1,
        )



def test_redis_outage_falls_back_to_authoritative_engine() -> None:
    _, engine, state, revocations, clock, request, _, _ = _setup()
    runtime = DistributedAuthorizationRuntime(
        engine=engine,
        security_state=state,
        cache=RedisAuthorizationCache(
            FailingRedisClient(),
            keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
        ),
        revocations=revocations,
        clock=clock,
    )

    decision = runtime.authorize(request)

    assert decision.allowed is True
    assert engine.calls == 1
