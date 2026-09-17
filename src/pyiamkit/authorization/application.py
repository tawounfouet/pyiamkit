"""Application orchestration for Roles and Permissions."""

from pyiamkit.shared import Clock, DomainEvent, DomainEventSink
from pyiamkit.tenancy import TenantId

from .domain.errors import (
    PermissionAlreadyExists,
    PermissionNotFound,
    RoleAlreadyExists,
    RoleNotFound,
)
from .domain.events import AuthorizationCatalogEventType
from .domain.permission import Permission
from .domain.role import Role
from .domain.value_objects import PermissionCode, RoleId, RoleType
from .ports import PermissionCatalogRepository, RoleRepository


class RoleCatalogApplicationService:
    """Coordinates permission registration and Role aggregate mutations."""

    def __init__(
        self,
        *,
        role_repository: RoleRepository,
        permission_repository: PermissionCatalogRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._roles = role_repository
        self._permissions = permission_repository
        self._clock = clock
        self._events = event_sink

    def register_permission(
        self,
        code: str,
        *,
        description: str = "",
        sensitive: bool = False,
    ) -> Permission:
        permission_code = PermissionCode(code)
        if self._permissions.get(permission_code) is not None:
            raise PermissionAlreadyExists(permission_code)
        permission = Permission(permission_code, description, sensitive)
        self._permissions.save(permission)
        self._events.publish(
            (
                self._event(
                    AuthorizationCatalogEventType.PERMISSION_REGISTERED,
                    {"permission": str(permission_code), "sensitive": sensitive},
                ),
            )
        )
        return permission

    def create_role(
        self,
        *,
        name: str,
        role_type: RoleType,
        tenant_id: TenantId | None = None,
        assignable: bool = True,
        sensitive: bool = False,
    ) -> Role:
        if self._roles.find_by_name(tenant_id, name) is not None:
            raise RoleAlreadyExists(name)
        role = Role.create(
            name=name,
            role_type=role_type,
            tenant_id=tenant_id,
            assignable=assignable,
            sensitive=sensitive,
            created_at=self._clock.now(),
        )
        return self._save_role(role)

    def add_permission(self, role_id: RoleId, code: str) -> Role:
        role = self._require_role(role_id)
        permission_code = PermissionCode(code)
        if self._permissions.get(permission_code) is None:
            raise PermissionNotFound(permission_code)
        role.add_permission(permission_code, at=self._clock.now())
        return self._save_role(role)

    def remove_permission(self, role_id: RoleId, code: str) -> Role:
        role = self._require_role(role_id)
        permission_code = PermissionCode(code)
        role.remove_permission(permission_code, at=self._clock.now())
        return self._save_role(role)

    def disable_role(self, role_id: RoleId) -> Role:
        role = self._require_role(role_id)
        role.disable(at=self._clock.now())
        return self._save_role(role)

    def set_role_sensitive(self, role_id: RoleId, value: bool) -> Role:
        role = self._require_role(role_id)
        role.set_sensitive(value, at=self._clock.now())
        return self._save_role(role)

    def set_role_assignable(self, role_id: RoleId, value: bool) -> Role:
        role = self._require_role(role_id)
        role.set_assignable(value, at=self._clock.now())
        return self._save_role(role)

    def _require_role(self, role_id: RoleId) -> Role:
        role = self._roles.get(role_id)
        if role is None:
            raise RoleNotFound(role_id)
        return role

    def _save_role(self, role: Role) -> Role:
        events = role.pull_events()
        self._roles.save(role)
        self._events.publish(events)
        saved = self._roles.get(role.id)
        if saved is None:
            raise RuntimeError("Role repository did not return the persisted aggregate.")
        return saved

    def _event(
        self,
        event_type: AuthorizationCatalogEventType,
        metadata: dict[str, object],
    ) -> DomainEvent:
        return DomainEvent(
            event_type=event_type.value,
            occurred_at=self._clock.now(),
            metadata=metadata,
        )
