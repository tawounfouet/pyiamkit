from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    PermissionCode,
    Role,
    RoleHierarchyApplicationService,
    RoleHierarchyCycle,
    RoleHierarchyResolver,
    RoleHierarchyTenantMismatch,
    RoleType,
)
from pyiamkit.authorization.adapters import InMemoryRoleRepository
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _role(
    repository: InMemoryRoleRepository,
    *,
    name: str,
    tenant_id: TenantId | None,
) -> Role:
    role = Role.create(
        name=name,
        role_type=RoleType.SYSTEM if tenant_id is None else RoleType.TENANT,
        tenant_id=tenant_id,
        created_at=NOW,
    )
    role.pull_events()
    repository.save(role)
    return role


def _service(repository: InMemoryRoleRepository) -> RoleHierarchyApplicationService:
    return RoleHierarchyApplicationService(
        role_repository=repository,
        clock=FrozenClock(),
        event_sink=InMemoryDomainEventSink(),
    )


def test_tenant_role_can_inherit_global_parent() -> None:
    repository = InMemoryRoleRepository()
    tenant_id = TenantId.new()
    parent = _role(repository, name="Base Reader", tenant_id=None)
    child = _role(repository, name="Tenant Manager", tenant_id=tenant_id)

    saved = _service(repository).add_parent_role(child.id, parent.id)
    assert saved.parent_role_ids == frozenset({parent.id})


def test_cross_tenant_parent_is_rejected() -> None:
    repository = InMemoryRoleRepository()
    child = _role(repository, name="Tenant A", tenant_id=TenantId.new())
    parent = _role(repository, name="Tenant B", tenant_id=TenantId.new())

    with pytest.raises(RoleHierarchyTenantMismatch):
        _service(repository).add_parent_role(child.id, parent.id)


def test_global_role_cannot_inherit_tenant_parent() -> None:
    repository = InMemoryRoleRepository()
    child = _role(repository, name="Global", tenant_id=None)
    parent = _role(repository, name="Tenant", tenant_id=TenantId.new())

    with pytest.raises(RoleHierarchyTenantMismatch):
        _service(repository).add_parent_role(child.id, parent.id)


def test_cycle_is_rejected() -> None:
    repository = InMemoryRoleRepository()
    tenant_id = TenantId.new()
    first = _role(repository, name="First", tenant_id=tenant_id)
    second = _role(repository, name="Second", tenant_id=tenant_id)
    service = _service(repository)

    service.add_parent_role(first.id, second.id)
    with pytest.raises(RoleHierarchyCycle):
        service.add_parent_role(second.id, first.id)


def test_resolver_collects_transitive_permissions() -> None:
    repository = InMemoryRoleRepository()
    tenant_id = TenantId.new()
    base = _role(repository, name="Base", tenant_id=None)
    middle = _role(repository, name="Middle", tenant_id=tenant_id)
    leaf = _role(repository, name="Leaf", tenant_id=tenant_id)
    permission = PermissionCode("invoice.read")

    base.add_permission(permission, at=NOW)
    base.pull_events()
    repository.save(base)
    service = _service(repository)
    service.add_parent_role(middle.id, base.id)
    service.add_parent_role(leaf.id, middle.id)

    resolver = RoleHierarchyResolver(repository)
    assert resolver.effective_permissions(leaf.id) == frozenset({permission})
    path = resolver.permission_path(leaf.id, permission)
    assert path is not None
    assert tuple(role.id for role in path) == (leaf.id, middle.id, base.id)


def test_parent_can_be_removed() -> None:
    repository = InMemoryRoleRepository()
    tenant_id = TenantId.new()
    parent = _role(repository, name="Parent", tenant_id=tenant_id)
    child = _role(repository, name="Child", tenant_id=tenant_id)
    service = _service(repository)

    service.add_parent_role(child.id, parent.id)
    saved = service.remove_parent_role(child.id, parent.id)
    assert saved.parent_role_ids == frozenset()
