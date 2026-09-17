"""Role aggregate root."""

from datetime import datetime, timedelta

from pyiamkit.shared import DomainEvent
from pyiamkit.tenancy import TenantId

from .errors import (
    InvalidRoleName,
    PermissionAlreadyAssigned,
    PermissionNotAssigned,
    RoleHierarchyCycle,
    RoleInactive,
)
from .events import AuthorizationCatalogEventType
from .value_objects import PermissionCode, RoleId, RoleStatus, RoleType


class Role:
    """Named permission collection that may inherit capabilities from parent Roles."""

    __slots__ = (
        "_assignable",
        "_created_at",
        "_id",
        "_name",
        "_parent_role_ids",
        "_pending_events",
        "_permissions",
        "_role_type",
        "_sensitive",
        "_status",
        "_tenant_id",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        role_id: RoleId,
        version: int,
        name: str,
        role_type: RoleType,
        status: RoleStatus,
        tenant_id: TenantId | None,
        assignable: bool,
        sensitive: bool,
        permissions: frozenset[PermissionCode],
        parent_role_ids: frozenset[RoleId],
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self._require_utc(created_at, "created_at")
        self._require_utc(updated_at, "updated_at")
        self._id = role_id
        self._version = version
        self._name = self._normalize_name(name)
        self._role_type = role_type
        self._status = status
        self._tenant_id = tenant_id
        self._assignable = assignable
        self._sensitive = sensitive
        self._permissions = set(permissions)
        self._parent_role_ids = set(parent_role_ids)
        self._created_at = created_at
        self._updated_at = updated_at
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        *,
        name: str,
        role_type: RoleType,
        created_at: datetime,
        tenant_id: TenantId | None = None,
        assignable: bool = True,
        sensitive: bool = False,
    ) -> "Role":
        role = cls(
            role_id=RoleId.new(),
            version=0,
            name=name,
            role_type=role_type,
            status=RoleStatus.ACTIVE,
            tenant_id=tenant_id,
            assignable=assignable,
            sensitive=sensitive,
            permissions=frozenset(),
            parent_role_ids=frozenset(),
            created_at=created_at,
            updated_at=created_at,
        )
        role._record(AuthorizationCatalogEventType.ROLE_CREATED, created_at)
        return role

    @classmethod
    def _rehydrate(
        cls,
        *,
        role_id: RoleId,
        version: int,
        name: str,
        role_type: RoleType,
        status: RoleStatus,
        tenant_id: TenantId | None,
        assignable: bool,
        sensitive: bool,
        permissions: frozenset[PermissionCode],
        parent_role_ids: frozenset[RoleId],
        created_at: datetime,
        updated_at: datetime,
    ) -> "Role":
        return cls(
            role_id=role_id,
            version=version,
            name=name,
            role_type=role_type,
            status=status,
            tenant_id=tenant_id,
            assignable=assignable,
            sensitive=sensitive,
            permissions=permissions,
            parent_role_ids=parent_role_ids,
            created_at=created_at,
            updated_at=updated_at,
        )

    @property
    def assignable(self) -> bool:
        return self._assignable

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def id(self) -> RoleId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def parent_role_ids(self) -> frozenset[RoleId]:
        return frozenset(self._parent_role_ids)

    @property
    def permissions(self) -> frozenset[PermissionCode]:
        return frozenset(self._permissions)

    @property
    def role_type(self) -> RoleType:
        return self._role_type

    @property
    def sensitive(self) -> bool:
        return self._sensitive

    @property
    def status(self) -> RoleStatus:
        return self._status

    @property
    def tenant_id(self) -> TenantId | None:
        return self._tenant_id

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def version(self) -> int:
        return self._version

    def add_parent_role(self, parent_role_id: RoleId, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if parent_role_id == self.id:
            raise RoleHierarchyCycle(self.id, parent_role_id)
        if parent_role_id in self._parent_role_ids:
            return
        self._parent_role_ids.add(parent_role_id)
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_PARENT_ADDED,
            at,
            {"parent_role_id": str(parent_role_id)},
        )

    def remove_parent_role(self, parent_role_id: RoleId, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if parent_role_id not in self._parent_role_ids:
            return
        self._parent_role_ids.remove(parent_role_id)
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_PARENT_REMOVED,
            at,
            {"parent_role_id": str(parent_role_id)},
        )

    def add_permission(self, code: PermissionCode, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if code in self._permissions:
            raise PermissionAlreadyAssigned(code)
        self._permissions.add(code)
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_PERMISSION_ADDED,
            at,
            {"permission": str(code)},
        )

    def remove_permission(self, code: PermissionCode, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if code not in self._permissions:
            raise PermissionNotAssigned(code)
        self._permissions.remove(code)
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_PERMISSION_REMOVED,
            at,
            {"permission": str(code)},
        )

    def disable(self, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        self._status = RoleStatus.DISABLED
        self._touch(at)
        self._record(AuthorizationCatalogEventType.ROLE_DISABLED, at)

    def set_sensitive(self, value: bool, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if self._sensitive == value:
            return
        self._sensitive = value
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_SENSITIVITY_CHANGED,
            at,
            {"sensitive": value},
        )

    def set_assignable(self, value: bool, *, at: datetime) -> None:
        self._require_active()
        self._require_utc(at, "at")
        if self._assignable == value:
            return
        self._assignable = value
        self._touch(at)
        self._record(
            AuthorizationCatalogEventType.ROLE_ASSIGNABILITY_CHANGED,
            at,
            {"assignable": value},
        )

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _record(
        self,
        event_type: AuthorizationCatalogEventType,
        at: datetime,
        metadata: dict[str, object] | None = None,
    ) -> None:
        self._pending_events.append(
            DomainEvent(
                event_type=event_type.value,
                occurred_at=at,
                metadata={"role_id": str(self.id), **(metadata or {})},
            )
        )

    def _require_active(self) -> None:
        if self.status is not RoleStatus.ACTIVE:
            raise RoleInactive(self.id)

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    @staticmethod
    def _normalize_name(value: str) -> str:
        normalized = value.strip()
        if not 1 <= len(normalized) <= 255:
            raise InvalidRoleName()
        return normalized

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")
