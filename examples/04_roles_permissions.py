"""Minimal Roles and Permissions example."""

from pyiamkit.authorization import RoleCatalogApplicationService, RoleType
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink
from pyiamkit.shared import SystemClock

service = RoleCatalogApplicationService(
    role_repository=InMemoryRoleRepository(),
    permission_repository=InMemoryPermissionCatalogRepository(),
    clock=SystemClock(),
    event_sink=InMemoryDomainEventSink(),
)
service.register_permission("invoice.read", description="Read invoices")
service.register_permission("invoice.approve", description="Approve invoices", sensitive=True)

role = service.create_role(name="Finance Manager", role_type=RoleType.BUSINESS, sensitive=True)
role = service.add_permission(role.id, "invoice.read")
role = service.add_permission(role.id, "invoice.approve")

print(role.name, sorted(str(code) for code in role.permissions))
