"""Authorization persistence ports."""

from datetime import datetime
from typing import Protocol

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .domain.binding_value_objects import RoleBindingId
from .domain.permission import Permission
from .domain.role import Role
from .domain.role_binding import RoleBinding
from .domain.value_objects import PermissionCode, RoleId


class PermissionCatalogRepository(Protocol):
    def get(self, code: PermissionCode) -> Permission | None: ...
    def save(self, permission: Permission) -> None: ...


class RoleRepository(Protocol):
    def get(self, role_id: RoleId) -> Role | None: ...
    def save(self, role: Role) -> None: ...
    def find_by_name(self, tenant_id: TenantId | None, name: str) -> Role | None: ...


class RoleBindingRepository(Protocol):
    def get(self, binding_id: RoleBindingId) -> RoleBinding | None: ...
    def save(self, binding: RoleBinding) -> None: ...
    def find_for_subject(
        self, identity_id: IdentityId, tenant_id: TenantId
    ) -> tuple[RoleBinding, ...]: ...
    def find_active_for_subject(
        self, identity_id: IdentityId, tenant_id: TenantId, at: datetime
    ) -> tuple[RoleBinding, ...]: ...
