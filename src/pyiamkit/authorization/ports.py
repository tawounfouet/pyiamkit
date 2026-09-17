"""Roles and permissions persistence ports."""

from typing import Protocol

from pyiamkit.tenancy import TenantId

from .domain.permission import Permission
from .domain.role import Role
from .domain.value_objects import PermissionCode, RoleId


class PermissionCatalogRepository(Protocol):
    def get(self, code: PermissionCode) -> Permission | None: ...
    def save(self, permission: Permission) -> None: ...


class RoleRepository(Protocol):
    def get(self, role_id: RoleId) -> Role | None: ...
    def save(self, role: Role) -> None: ...
    def find_by_name(self, tenant_id: TenantId | None, name: str) -> Role | None: ...
