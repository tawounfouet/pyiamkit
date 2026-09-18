"""SCIM Group provisioning domain model."""

from datetime import datetime, timedelta

from pyiamkit.tenancy import TenantId

from .domain import ProvisioningResourceId, ProvisioningResourceStatus
from .errors import InvalidProvisioningResource, ProvisioningManagedStateConflict


class ProvisioningGroup:
    """Source-scoped SCIM Group with User-resource membership only."""

    __slots__ = (
        "_created_at",
        "_deleted_at",
        "_display_name",
        "_external_id",
        "_id",
        "_member_ids",
        "_source_id",
        "_status",
        "_tenant_id",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        resource_id: ProvisioningResourceId,
        version: int,
        source_id: str,
        tenant_id: TenantId,
        display_name: str,
        member_ids: tuple[ProvisioningResourceId, ...],
        status: ProvisioningResourceStatus,
        created_at: datetime,
        updated_at: datetime,
        external_id: str | None = None,
        deleted_at: datetime | None = None,
    ) -> None:
        self._require_utc(created_at, "created_at")
        self._require_utc(updated_at, "updated_at")
        if deleted_at is not None:
            self._require_utc(deleted_at, "deleted_at")
        source_id = source_id.strip()
        display_name = display_name.strip()
        if not source_id:
            raise InvalidProvisioningResource("source_id must not be empty")
        if not display_name:
            raise InvalidProvisioningResource("display_name must not be empty")
        if version < 0:
            raise InvalidProvisioningResource("version must not be negative")
        if status is ProvisioningResourceStatus.DELETED and deleted_at is None:
            raise InvalidProvisioningResource("deleted resources require deleted_at")
        self._id = resource_id
        self._version = version
        self._source_id = source_id
        self._tenant_id = tenant_id
        self._display_name = display_name
        self._external_id = _optional_text(external_id)
        self._member_ids = frozenset(member_ids)
        self._status = status
        self._created_at = created_at
        self._updated_at = updated_at
        self._deleted_at = deleted_at

    @classmethod
    def create(
        cls,
        *,
        source_id: str,
        tenant_id: TenantId,
        display_name: str,
        member_ids: tuple[ProvisioningResourceId, ...],
        created_at: datetime,
        external_id: str | None = None,
    ) -> "ProvisioningGroup":
        return cls(
            resource_id=ProvisioningResourceId.new(),
            version=0,
            source_id=source_id,
            tenant_id=tenant_id,
            display_name=display_name,
            member_ids=member_ids,
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=created_at,
            updated_at=created_at,
            external_id=external_id,
        )

    @classmethod
    def _rehydrate(
        cls,
        *,
        resource_id: ProvisioningResourceId,
        version: int,
        source_id: str,
        tenant_id: TenantId,
        display_name: str,
        member_ids: tuple[ProvisioningResourceId, ...],
        status: ProvisioningResourceStatus,
        created_at: datetime,
        updated_at: datetime,
        external_id: str | None,
        deleted_at: datetime | None,
    ) -> "ProvisioningGroup":
        return cls(
            resource_id=resource_id,
            version=version,
            source_id=source_id,
            tenant_id=tenant_id,
            display_name=display_name,
            member_ids=member_ids,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            external_id=external_id,
            deleted_at=deleted_at,
        )

    @property
    def id(self) -> ProvisioningResourceId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def source_id(self) -> str:
        return self._source_id

    @property
    def tenant_id(self) -> TenantId:
        return self._tenant_id

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def external_id(self) -> str | None:
        return self._external_id

    @property
    def member_ids(self) -> tuple[ProvisioningResourceId, ...]:
        return tuple(sorted(self._member_ids, key=str))

    @property
    def status(self) -> ProvisioningResourceStatus:
        return self._status

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def deleted_at(self) -> datetime | None:
        return self._deleted_at

    @property
    def etag(self) -> str:
        return f'W/"{self.id}-{self.version}"'

    def replace(
        self,
        *,
        display_name: str,
        external_id: str | None,
        member_ids: tuple[ProvisioningResourceId, ...],
        at: datetime,
    ) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        display_name = display_name.strip()
        if not display_name:
            raise InvalidProvisioningResource("display_name must not be empty")
        self._display_name = display_name
        self._external_id = _optional_text(external_id)
        self._member_ids = frozenset(member_ids)
        self._touch(at)

    def add_members(
        self,
        member_ids: tuple[ProvisioningResourceId, ...],
        *,
        at: datetime,
    ) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        updated = self._member_ids.union(member_ids)
        if updated != self._member_ids:
            self._member_ids = frozenset(updated)
            self._touch(at)

    def remove_members(
        self,
        member_ids: tuple[ProvisioningResourceId, ...],
        *,
        at: datetime,
    ) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        updated = self._member_ids.difference(member_ids)
        if updated != self._member_ids:
            self._member_ids = frozenset(updated)
            self._touch(at)

    def replace_members(
        self,
        member_ids: tuple[ProvisioningResourceId, ...],
        *,
        at: datetime,
    ) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        updated = frozenset(member_ids)
        if updated != self._member_ids:
            self._member_ids = updated
            self._touch(at)

    def rename(self, display_name: str, *, at: datetime) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        normalized = display_name.strip()
        if not normalized:
            raise InvalidProvisioningResource("display_name must not be empty")
        if normalized != self._display_name:
            self._display_name = normalized
            self._touch(at)

    def set_external_id(self, external_id: str | None, *, at: datetime) -> None:
        self._ensure_mutable()
        self._require_utc(at, "at")
        normalized = _optional_text(external_id)
        if normalized != self._external_id:
            self._external_id = normalized
            self._touch(at)

    def delete(self, *, at: datetime) -> None:
        if self.status is ProvisioningResourceStatus.DELETED:
            return
        self._require_utc(at, "at")
        self._status = ProvisioningResourceStatus.DELETED
        self._deleted_at = at
        self._member_ids = frozenset()
        self._touch(at)

    def _ensure_mutable(self) -> None:
        if self.status is ProvisioningResourceStatus.DELETED:
            raise ProvisioningManagedStateConflict("Deleted provisioning groups are immutable")

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise InvalidProvisioningResource(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProvisioningGroup):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
