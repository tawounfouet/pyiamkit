"""Tenant aggregate root."""

from collections.abc import Mapping
from datetime import datetime, timedelta
from types import MappingProxyType

from pyiamkit.shared import DomainEvent

from .errors import InvalidTenant, InvalidTenantTransition
from .events import TenancyEventType
from .value_objects import TenantId, TenantStatus


class Tenant:
    __slots__ = (
        "_created_at",
        "_id",
        "_metadata",
        "_name",
        "_pending_events",
        "_slug",
        "_status",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        tenant_id: TenantId,
        version: int,
        name: str,
        slug: str,
        status: TenantStatus,
        created_at: datetime,
        updated_at: datetime,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        self._require_utc(created_at, "created_at")
        self._require_utc(updated_at, "updated_at")
        self._id = tenant_id
        self._version = version
        self._name = self._normalize_name(name)
        self._slug = self._normalize_slug(slug)
        self._status = status
        self._created_at = created_at
        self._updated_at = updated_at
        self._metadata = MappingProxyType(dict(metadata or {}))
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(
        cls,
        *,
        name: str,
        slug: str,
        created_at: datetime,
        metadata: Mapping[str, object] | None = None,
    ) -> "Tenant":
        tenant = cls(
            tenant_id=TenantId.new(),
            version=0,
            name=name,
            slug=slug,
            status=TenantStatus.PENDING,
            created_at=created_at,
            updated_at=created_at,
            metadata=metadata,
        )
        tenant._record(TenancyEventType.TENANT_CREATED, created_at)
        return tenant

    @classmethod
    def _rehydrate(
        cls,
        *,
        tenant_id: TenantId,
        version: int,
        name: str,
        slug: str,
        status: TenantStatus,
        created_at: datetime,
        updated_at: datetime,
        metadata: Mapping[str, object],
    ) -> "Tenant":
        return cls(
            tenant_id=tenant_id,
            version=version,
            name=name,
            slug=slug,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            metadata=metadata,
        )

    @property
    def id(self) -> TenantId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def name(self) -> str:
        return self._name

    @property
    def slug(self) -> str:
        return self._slug

    @property
    def status(self) -> TenantStatus:
        return self._status

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def metadata(self) -> Mapping[str, object]:
        return self._metadata

    def activate(self, *, at: datetime) -> None:
        self._transition(
            TenantStatus.PENDING,
            TenantStatus.ACTIVE,
            "activate",
            at,
            TenancyEventType.TENANT_ACTIVATED,
        )

    def suspend(self, *, at: datetime) -> None:
        self._transition(
            TenantStatus.ACTIVE,
            TenantStatus.SUSPENDED,
            "suspend",
            at,
            TenancyEventType.TENANT_SUSPENDED,
        )

    def reactivate(self, *, at: datetime) -> None:
        self._transition(
            TenantStatus.SUSPENDED,
            TenantStatus.ACTIVE,
            "reactivate",
            at,
            TenancyEventType.TENANT_REACTIVATED,
        )

    def disable(self, *, at: datetime) -> None:
        if self.status not in {TenantStatus.ACTIVE, TenantStatus.SUSPENDED}:
            raise InvalidTenantTransition(self.status.value, "disable")
        self._set_status(TenantStatus.DISABLED, at, TenancyEventType.TENANT_DISABLED)

    def archive(self, *, at: datetime) -> None:
        self._transition(
            TenantStatus.DISABLED,
            TenantStatus.ARCHIVED,
            "archive",
            at,
            TenancyEventType.TENANT_ARCHIVED,
        )

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _transition(
        self,
        expected: TenantStatus,
        target: TenantStatus,
        action: str,
        at: datetime,
        event_type: TenancyEventType,
    ) -> None:
        if self.status is not expected:
            raise InvalidTenantTransition(self.status.value, action)
        self._set_status(target, at, event_type)

    def _set_status(
        self,
        status: TenantStatus,
        at: datetime,
        event_type: TenancyEventType,
    ) -> None:
        self._require_utc(at, "at")
        self._status = status
        self._version += 1
        self._updated_at = at
        self._record(event_type, at)

    def _record(self, event_type: TenancyEventType, at: datetime) -> None:
        self._pending_events.append(
            DomainEvent(
                event_type=event_type.value,
                occurred_at=at,
                metadata={"tenant_id": str(self.id)},
            )
        )

    @staticmethod
    def _normalize_name(value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 255:
            raise InvalidTenant("Tenant name must contain between 1 and 255 characters.")
        return value

    @staticmethod
    def _normalize_slug(value: str) -> str:
        value = value.strip().lower()
        if not 1 <= len(value) <= 63 or value.startswith("-") or value.endswith("-"):
            raise InvalidTenant("Tenant slug must contain between 1 and 63 valid characters.")
        if any(not (char.isalnum() or char == "-") for char in value):
            raise InvalidTenant("Tenant slug may only contain letters, digits and hyphens.")
        return value

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")
