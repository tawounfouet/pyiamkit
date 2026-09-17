from datetime import UTC, datetime

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import Membership, Tenant
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_tenant_repository_returns_database_like_copy() -> None:
    repository = InMemoryTenantRepository()
    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    tenant.pull_events()
    repository.save(tenant)

    loaded = repository.get(tenant.id)
    assert loaded == loaded
    assert loaded is not tenant
    assert loaded is not None
    assert loaded.id == tenant.id


def test_membership_repository_is_tenant_aware() -> None:
    repository = InMemoryMembershipRepository()
    identity_id = IdentityId.new()
    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    other = Tenant.create(name="OTHER", slug="other", created_at=NOW)
    membership = Membership.create(identity_id=identity_id, tenant_id=tenant.id, created_at=NOW)
    membership.activate(at=NOW)
    membership.pull_events()
    repository.save(membership)

    assert repository.find_active(identity_id, tenant.id, NOW) is not None
    assert repository.find_active(identity_id, other.id, NOW) is None
