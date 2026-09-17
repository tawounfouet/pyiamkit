from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    PermissionAlreadyExists,
    PermissionNotFound,
    RoleAlreadyExists,
    RoleCatalogApplicationService,
    RoleId,
    RoleNotFound,
    RoleStatus,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink
from pyiamkit.shared import Clock
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _service() -> RoleCatalogApplicationService:
    return RoleCatalogApplicationService(
        role_repository=InMemoryRoleRepository(),
        permission_repository=InMemoryPermissionCatalogRepository(),
        clock=FrozenClock(),
        event_sink=InMemoryDomainEventSink(),
    )


def test_register_permission_and_add_it_to_role() -> None:
    service = _service()
    service.register_permission("invoice.read", description="Read invoices")
    role = service.create_role(name="Reader", role_type=RoleType.BUSINESS)
    role = service.add_permission(role.id, "invoice.read")
    assert {str(code) for code in role.permissions} == {"invoice.read"}


def test_duplicate_permission_registration_is_rejected() -> None:
    service = _service()
    service.register_permission("invoice.read")
    with pytest.raises(PermissionAlreadyExists):
        service.register_permission("invoice.read")


def test_unknown_permission_cannot_be_added_to_role() -> None:
    service = _service()
    role = service.create_role(name="Reader", role_type=RoleType.BUSINESS)
    with pytest.raises(PermissionNotFound):
        service.add_permission(role.id, "invoice.read")


def test_role_name_is_unique_within_same_tenant_but_not_across_tenants() -> None:
    service = _service()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()
    service.create_role(name="Manager", role_type=RoleType.TENANT, tenant_id=tenant_a)
    service.create_role(name="Manager", role_type=RoleType.TENANT, tenant_id=tenant_b)

    with pytest.raises(RoleAlreadyExists):
        service.create_role(name="manager", role_type=RoleType.TENANT, tenant_id=tenant_a)


def test_service_can_remove_permission_and_disable_role() -> None:
    service = _service()
    service.register_permission("invoice.read")
    role = service.create_role(name="Reader", role_type=RoleType.BUSINESS)
    role = service.add_permission(role.id, "invoice.read")
    role = service.remove_permission(role.id, "invoice.read")
    assert not role.permissions

    role = service.disable_role(role.id)
    assert role.status is RoleStatus.DISABLED


def test_service_can_change_role_governance_flags() -> None:
    service = _service()
    role = service.create_role(name="Admin Base", role_type=RoleType.SYSTEM)
    role = service.set_role_sensitive(role.id, True)
    role = service.set_role_assignable(role.id, False)
    assert role.sensitive is True
    assert role.assignable is False


def test_unknown_role_is_rejected() -> None:
    service = _service()
    with pytest.raises(RoleNotFound):
        service.disable_role(RoleId.new())
