"""In-memory adapters for the authorization model."""

from datetime import datetime

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from ..domain.binding_value_objects import RoleBindingId
from ..domain.permission import Permission
from ..domain.role import Role
from ..domain.role_binding import RoleBinding
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
            parent_role_ids=role.parent_role_ids,
            created_at=role.created_at,
            updated_at=role.updated_at,
        )


class InMemoryRoleBindingRepository:
    def __init__(self) -> None:
        self._items: dict[RoleBindingId, RoleBinding] = {}

    def get(self, binding_id: RoleBindingId) -> RoleBinding | None:
        binding = self._items.get(binding_id)
        return None if binding is None else self._copy(binding)

    def save(self, binding: RoleBinding) -> None:
        self._items[binding.id] = self._copy(binding)

    def find_for_subject(
        self, identity_id: IdentityId, tenant_id: TenantId
    ) -> tuple[RoleBinding, ...]:
        return tuple(
            self._copy(binding)
            for binding in self._items.values()
            if binding.identity_id == identity_id and binding.tenant_id == tenant_id
        )

    def find_active_for_subject(
        self, identity_id: IdentityId, tenant_id: TenantId, at: datetime
    ) -> tuple[RoleBinding, ...]:
        return tuple(
            binding
            for binding in self.find_for_subject(identity_id, tenant_id)
            if binding.is_active(at=at)
        )

    @staticmethod
    def _copy(binding: RoleBinding) -> RoleBinding:
        return RoleBinding._rehydrate(
            binding_id=binding.id,
            version=binding.version,
            identity_id=binding.identity_id,
            role_id=binding.role_id,
            tenant_id=binding.tenant_id,
            scope=binding.scope,
            status=binding.status,
            grant_source=binding.grant_source,
            granted_by=binding.granted_by,
            justification=binding.justification,
            created_at=binding.created_at,
            updated_at=binding.updated_at,
            valid_from=binding.valid_from,
            valid_until=binding.valid_until,
        )
