from concurrent.futures import ThreadPoolExecutor

from pyiamkit.identity import IdentityId
from pyiamkit.operations import SecurityStateReader, SecurityStateWriter, StateVersion
from pyiamkit.operations.adapters import InMemorySecurityStateStore
from pyiamkit.tenancy import TenantId


def _assert_contracts(
    reader: SecurityStateReader,
    writer: SecurityStateWriter,
) -> None:
    assert reader is writer


def test_in_memory_store_implements_reader_and_writer_contracts() -> None:
    store = InMemorySecurityStateStore()

    _assert_contracts(store, store)


def test_empty_store_returns_zero_security_stamp() -> None:
    store = InMemorySecurityStateStore()

    stamp = store.stamp_for(
        identity_id=IdentityId.new(),
        tenant_id=TenantId.new(),
    )

    assert stamp.runtime_generation == StateVersion(0)
    assert stamp.identity == StateVersion(0)
    assert stamp.tenant == StateVersion(0)
    assert stamp.membership == StateVersion(0)
    assert stamp.subject_authorization == StateVersion(0)
    assert stamp.tenant_authorization == StateVersion(0)
    assert stamp.global_authorization == StateVersion(0)
    assert stamp.governance == StateVersion(0)
    assert stamp.authentication == StateVersion(0)


def test_security_state_versions_are_monotonic_per_dimension() -> None:
    store = InMemorySecurityStateStore()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    assert store.bump_identity(identity_id) == StateVersion(1)
    assert store.bump_identity(identity_id) == StateVersion(2)
    assert store.bump_tenant(tenant_id) == StateVersion(1)
    assert store.bump_membership(identity_id, tenant_id) == StateVersion(1)
    assert store.bump_subject_authorization(identity_id, tenant_id) == StateVersion(1)
    assert store.bump_tenant_authorization(tenant_id) == StateVersion(1)
    assert store.bump_global_authorization() == StateVersion(1)
    assert store.bump_governance(tenant_id) == StateVersion(1)
    assert store.bump_authentication(identity_id) == StateVersion(1)
    assert store.bump_runtime_generation() == StateVersion(1)

    stamp = store.stamp_for(identity_id=identity_id, tenant_id=tenant_id)

    assert stamp.runtime_generation == StateVersion(1)
    assert stamp.identity == StateVersion(2)
    assert stamp.tenant == StateVersion(1)
    assert stamp.membership == StateVersion(1)
    assert stamp.subject_authorization == StateVersion(1)
    assert stamp.tenant_authorization == StateVersion(1)
    assert stamp.global_authorization == StateVersion(1)
    assert stamp.governance == StateVersion(1)
    assert stamp.authentication == StateVersion(1)


def test_identity_scoped_versions_do_not_leak_between_subjects() -> None:
    store = InMemorySecurityStateStore()
    identity_a = IdentityId.new()
    identity_b = IdentityId.new()
    tenant_id = TenantId.new()

    store.bump_identity(identity_a)
    store.bump_authentication(identity_a)

    stamp_a = store.stamp_for(identity_id=identity_a, tenant_id=tenant_id)
    stamp_b = store.stamp_for(identity_id=identity_b, tenant_id=tenant_id)

    assert stamp_a.identity == StateVersion(1)
    assert stamp_a.authentication == StateVersion(1)
    assert stamp_b.identity == StateVersion(0)
    assert stamp_b.authentication == StateVersion(0)


def test_tenant_scoped_versions_do_not_leak_between_tenants() -> None:
    store = InMemorySecurityStateStore()
    identity_id = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    store.bump_tenant(tenant_a)
    store.bump_tenant_authorization(tenant_a)
    store.bump_governance(tenant_a)

    stamp_a = store.stamp_for(identity_id=identity_id, tenant_id=tenant_a)
    stamp_b = store.stamp_for(identity_id=identity_id, tenant_id=tenant_b)

    assert stamp_a.tenant == StateVersion(1)
    assert stamp_a.tenant_authorization == StateVersion(1)
    assert stamp_a.governance == StateVersion(1)
    assert stamp_b.tenant == StateVersion(0)
    assert stamp_b.tenant_authorization == StateVersion(0)
    assert stamp_b.governance == StateVersion(0)


def test_subject_tenant_versions_are_isolated_by_both_keys() -> None:
    store = InMemorySecurityStateStore()
    identity_a = IdentityId.new()
    identity_b = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    store.bump_membership(identity_a, tenant_a)
    store.bump_subject_authorization(identity_a, tenant_a)

    expected = store.stamp_for(identity_id=identity_a, tenant_id=tenant_a)
    other_subject = store.stamp_for(identity_id=identity_b, tenant_id=tenant_a)
    other_tenant = store.stamp_for(identity_id=identity_a, tenant_id=tenant_b)

    assert expected.membership == StateVersion(1)
    assert expected.subject_authorization == StateVersion(1)
    assert other_subject.membership == StateVersion(0)
    assert other_subject.subject_authorization == StateVersion(0)
    assert other_tenant.membership == StateVersion(0)
    assert other_tenant.subject_authorization == StateVersion(0)


def test_global_versions_are_visible_to_every_stamp() -> None:
    store = InMemorySecurityStateStore()
    identity_a = IdentityId.new()
    identity_b = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    store.bump_runtime_generation()
    store.bump_global_authorization()

    stamp_a = store.stamp_for(identity_id=identity_a, tenant_id=tenant_a)
    stamp_b = store.stamp_for(identity_id=identity_b, tenant_id=tenant_b)

    assert stamp_a.runtime_generation == stamp_b.runtime_generation == StateVersion(1)
    assert stamp_a.global_authorization == stamp_b.global_authorization == StateVersion(1)


def test_concurrent_bumps_do_not_lose_updates() -> None:
    store = InMemorySecurityStateStore()
    identity_id = IdentityId.new()

    with ThreadPoolExecutor(max_workers=8) as executor:
        versions = tuple(executor.map(lambda _: store.bump_identity(identity_id), range(100)))

    assert {version.value for version in versions} == set(range(1, 101))
    stamp = store.stamp_for(identity_id=identity_id, tenant_id=TenantId.new())
    assert stamp.identity == StateVersion(100)
