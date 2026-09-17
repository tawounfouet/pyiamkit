"""In-memory adapters for the Roles and Permissions model."""

from pyiamkit.tenancy import TenantId

from ..domain.permission import Permission
from ..domain.role import Role
from ..domain.value_objects import PermissionCode, RoleId


class InMemoryPermissionCatalogRepository:
    def __init__(self) -> None:
        self._items: dict[PermissionCode, Permission] = {}

    def get(self, code: PermissionCode) -> Permission | None:
        return self._items.get(code)

    def save(self, permission: Permission) -> None:
        self._items[permission.code] = permission


class InMemoryRoleRepository:
    def __init__(self) -> None:
        self._items: dict[RoleId, Role] = {}

    def get(self, role_id: RoleId) -> Role | None:
        role = self._items.get(role_id)
        return None if role is None else self._copy(role)

    def save(self, role: Role) -> None:
        self._items[role.id] = self._copy(role)

    def find_by_name(self, tenant_id: TenantId | None, name: str) -> Role | None:
        normalized = name.strip().casefold()
        for role in self._items.values():
            if role.tenant_id == tenant_id and role.name.casefold() == normalized:
                return self._copy(role)
        return None

    @staticmethod
    def _copy(role: Role) -> Role:
        return Role._rehydrate(
            role_id=role.id,
            version=role.version,
            name=role.name,
            role_type=role.role_type,
            status=role.status,
            tenant_id=role.tenant_id,
            assignable=role.assignable,
            sensitive=role.sensitive,
            permissions=role.permissions,
            created_at=role.created_at,
            updated_at=role.updated_at,
        )
