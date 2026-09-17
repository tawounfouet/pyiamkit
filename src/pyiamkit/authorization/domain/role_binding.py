"""RoleBinding aggregate root."""

from datetime import datetime, timedelta

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent
from pyiamkit.tenancy import TenantId, TenantScope

from .binding_value_objects import GrantSource, RoleBindingId, RoleBindingStatus
from .errors import InvalidRoleBinding, InvalidRoleBindingTransition
from .events import AuthorizationCatalogEventType
from .value_objects import RoleId


class RoleBinding:
    """Scoped assignment of a Role to an Identity within a Tenant."""

    __slots__ = (
        "_created_at",
        "_grant_source",
        "_granted_by",
        "_id",
        "_identity_id",
        "_justification",
        "_pending_events",
        "_role_id",
        "_scope",
        "_status",
        "_tenant_id",
        "_updated_at",
        "_valid_from",
        "_valid_until",
        "_version",
    )

    def __init__(
        self,
        *,
        binding_id: RoleBindingId,
        version: int,
        identity_id: IdentityId,
        role_id: RoleId,
        tenant_id: TenantId,
        scope: TenantScope,
        status: RoleBindingStatus,
        grant_source: GrantSource,
        granted_by: IdentityId | None,
        justification: str | None,
        created_at: datetime,
        updated_at: datetime,
        valid_from: datetime,
        valid_until: datetime | None,
    ) -> None:
        for name, value in (
            ("created_at", created_at),
            ("updated_at", updated_at),
            ("valid_from", valid_from),
        ):
            self._require_utc(value, name)
        if scope.tenant_id != tenant_id:
            raise InvalidRoleBinding("RoleBinding scope must belong to its tenant.")
        if valid_until is not None:
            self._require_utc(valid_until, "valid_until")
            if valid_until <= valid_from:
                raise InvalidRoleBinding("valid_until must be after valid_from.")
        self._id = binding_id
        self._version = version
        self._identity_id = identity_id
        self._role_id = role_id
        self._tenant_id = tenant_id
        self._scope = scope
        self._status = status
        self._grant_source = grant_source
        self._granted_by = granted_by
        self._justification = self._normalize_justification(justification)
        self._created_at = created_at
        self._updated_at = updated_at
        self._valid_from = valid_from
        self._valid_until = valid_until
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        *,
        identity_id: IdentityId,
        role_id: RoleId,
        tenant_id: TenantId,
        scope: TenantScope,
        created_at: datetime,
        valid_until: datetime | None = None,
        grant_source: GrantSource = GrantSource.DIRECT,
        granted_by: IdentityId | None = None,
        justification: str | None = None,
    ) -> "RoleBinding":
        binding = cls(
            binding_id=RoleBindingId.new(),
            version=0,
            identity_id=identity_id,
            role_id=role_id,
            tenant_id=tenant_id,
            scope=scope,
            status=RoleBindingStatus.ACTIVE,
            grant_source=grant_source,
            granted_by=granted_by,
            justification=justification,
            created_at=created_at,
            updated_at=created_at,
            valid_from=created_at,
            valid_until=valid_until,
        )
        binding._record(AuthorizationCatalogEventType.ROLE_ASSIGNED, created_at)
        return binding

    @classmethod
    def _rehydrate(
        cls,
        *,
        binding_id: RoleBindingId,
        version: int,
        identity_id: IdentityId,
        role_id: RoleId,
        tenant_id: TenantId,
        scope: TenantScope,
        status: RoleBindingStatus,
        grant_source: GrantSource,
        granted_by: IdentityId | None,
        justification: str | None,
        created_at: datetime,
        updated_at: datetime,
        valid_from: datetime,
        valid_until: datetime | None,
    ) -> "RoleBinding":
        return cls(
            binding_id=binding_id,
            version=version,
            identity_id=identity_id,
            role_id=role_id,
            tenant_id=tenant_id,
            scope=scope,
            status=status,
            grant_source=grant_source,
            granted_by=granted_by,
            justification=justification,
            created_at=created_at,
            updated_at=updated_at,
            valid_from=valid_from,
            valid_until=valid_until,
        )

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def grant_source(self) -> GrantSource:
        return self._grant_source

    @property
    def granted_by(self) -> IdentityId | None:
        return self._granted_by

    @property
    def id(self) -> RoleBindingId:
        return self._id

    @property
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def justification(self) -> str | None:
        return self._justification

    @property
    def role_id(self) -> RoleId:
        return self._role_id

    @property
    def scope(self) -> TenantScope:
        return self._scope

    @property
    def status(self) -> RoleBindingStatus:
        return self._status

    @property
    def tenant_id(self) -> TenantId:
        return self._tenant_id

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def valid_from(self) -> datetime:
        return self._valid_from

    @property
    def valid_until(self) -> datetime | None:
        return self._valid_until

    @property
    def version(self) -> int:
        return self._version

    def is_active(self, *, at: datetime) -> bool:
        self._require_utc(at, "at")
        return (
            self.status is RoleBindingStatus.ACTIVE
            and self.valid_from <= at
            and (self.valid_until is None or at < self.valid_until)
        )

    def suspend(self, *, at: datetime) -> None:
        self._transition(
            RoleBindingStatus.ACTIVE,
            RoleBindingStatus.SUSPENDED,
            "suspend",
            at,
            AuthorizationCatalogEventType.ROLE_BINDING_SUSPENDED,
        )

    def reactivate(self, *, at: datetime) -> None:
        self._transition(
            RoleBindingStatus.SUSPENDED,
            RoleBindingStatus.ACTIVE,
            "reactivate",
            at,
            AuthorizationCatalogEventType.ROLE_BINDING_REACTIVATED,
        )

    def revoke(self, *, at: datetime) -> None:
        if self.status not in {RoleBindingStatus.ACTIVE, RoleBindingStatus.SUSPENDED}:
            raise InvalidRoleBindingTransition(self.status.value, "revoke")
        self._set_status(
            RoleBindingStatus.REVOKED,
            at,
            AuthorizationCatalogEventType.ROLE_BINDING_REVOKED,
        )

    def expire(self, *, at: datetime) -> None:
        if self.status not in {RoleBindingStatus.ACTIVE, RoleBindingStatus.SUSPENDED}:
            raise InvalidRoleBindingTransition(self.status.value, "expire")
        self._set_status(
            RoleBindingStatus.EXPIRED,
            at,
            AuthorizationCatalogEventType.ROLE_BINDING_EXPIRED,
        )

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _transition(
        self,
        expected: RoleBindingStatus,
        target: RoleBindingStatus,
        action: str,
        at: datetime,
        event_type: AuthorizationCatalogEventType,
    ) -> None:
        if self.status is not expected:
            raise InvalidRoleBindingTransition(self.status.value, action)
        self._set_status(target, at, event_type)

    def _set_status(
        self,
        status: RoleBindingStatus,
        at: datetime,
        event_type: AuthorizationCatalogEventType,
    ) -> None:
        self._require_utc(at, "at")
        self._status = status
        self._version += 1
        self._updated_at = at
        self._record(event_type, at)

    def _record(self, event_type: AuthorizationCatalogEventType, at: datetime) -> None:
        self._pending_events.append(
            DomainEvent(
                event_type=event_type.value,
                occurred_at=at,
                metadata={
                    "binding_id": str(self.id),
                    "identity_id": str(self.identity_id),
                    "role_id": str(self.role_id),
                    "tenant_id": str(self.tenant_id),
                },
            )
        )

    @staticmethod
    def _normalize_justification(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")
