from datetime import UTC, datetime

from pyiamkit.authorization import Permission, PermissionCode, Role, RoleType
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleRepository,
)
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_permission_catalog_round_trip() -> None:
    repository = InMemoryPermissionCatalogRepository()
    permission = Permission(PermissionCode("invoice.read"), "Read invoices")
    repository.save(permission)
    assert repository.get(permission.code) == permission


def test_role_repository_has_database_like_copy_semantics() -> None:
    repository = InMemoryRoleRepository()
    role = Role.create(name="Reader", role_type=RoleType.BUSINESS, created_at=NOW)
    role.pull_events()
    repository.save(role)
    loaded = repository.get(role.id)

    assert loaded is not None
    assert loaded is not role
    assert loaded.id == role.id


def test_role_lookup_is_partitioned_by_tenant() -> None:
    repository = InMemoryRoleRepository()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()
    role = Role.create(
        name="Manager", role_type=RoleType.TENANT, tenant_id=tenant_a, created_at=NOW
    )
    role.pull_events()
    repository.save(role)

    assert repository.find_by_name(tenant_a, "manager") is not None
    assert repository.find_by_name(tenant_b, "manager") is None
