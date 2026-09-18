"""Provisioning resource domain model."""

from datetime import datetime, timedelta
from enum import StrEnum

from pyiamkit.identity import IdentityId
from pyiamkit.shared import EntityId
from pyiamkit.tenancy import MembershipId, TenantId

from .errors import InvalidProvisioningResource, ProvisioningManagedStateConflict


class ProvisioningResourceId(EntityId):
    """Stable service-provider identifier exposed as the SCIM resource id."""


class ProvisioningResourceStatus(StrEnum):
    ACTIVE = "active"
    DELETED = "deleted"


class ProvisioningUser:
    """Tenant-scoped mapping between one provisioning source and a local user."""

    __slots__ = (
        "_active",
        "_created_at",
        "_deleted_at",
        "_external_id",
        "_id",
        "_identity_id",
        "_membership_id",
        "_source_id",
        "_status",
        "_tenant_id",
        "_updated_at",
        "_user_name",
        "_version",
    )

    def __init__(
        self,
        *,
        resource_id: ProvisioningResourceId,
        version: int,
        source_id: str,
        identity_id: IdentityId,
        tenant_id: TenantId,
        membership_id: MembershipId,
        user_name: str,
        active: bool,
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
        user_name = user_name.strip()
        external_id = _optional_text(external_id)
        if not source_id:
            raise InvalidProvisioningResource("source_id must not be empty")
        if not user_name:
            raise InvalidProvisioningResource("user_name must not be empty")
        if status is ProvisioningResourceStatus.DELETED and deleted_at is None:
            raise InvalidProvisioningResource("deleted resources require deleted_at")
        self._id = resource_id
        self._version = version
        self._source_id = source_id
        self._identity_id = identity_id
        self._tenant_id = tenant_id
        self._membership_id = membership_id
        self._user_name = user_name
        self._external_id = external_id
        self._active = active
        self._status = status
        self._created_at = created_at
        self._updated_at = updated_at
        self._deleted_at = deleted_at

    @classmethod
    def create(
        cls,
        *,
        source_id: str,
        identity_id: IdentityId,
        tenant_id: TenantId,
        membership_id: MembershipId,
        user_name: str,
        active: bool,
        created_at: datetime,
        external_id: str | None = None,
    ) -> "ProvisioningUser":
        return cls(
            resource_id=ProvisioningResourceId.new(),
            version=0,
            source_id=source_id,
            identity_id=identity_id,
            tenant_id=tenant_id,
            membership_id=membership_id,
            user_name=user_name,
            active=active,
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
        identity_id: IdentityId,
        tenant_id: TenantId,
        membership_id: MembershipId,
        user_name: str,
        active: bool,
        status: ProvisioningResourceStatus,
        created_at: datetime,
        updated_at: datetime,
        external_id: str | None,
        deleted_at: datetime | None,
    ) -> "ProvisioningUser":
        return cls(
            resource_id=resource_id,
            version=version,
            source_id=source_id,
            identity_id=identity_id,
            tenant_id=tenant_id,
            membership_id=membership_id,
            user_name=user_name,
            active=active,
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
    def identity_id(self) -> IdentityId:
        return self._identity_id

    @property
    def tenant_id(self) -> TenantId:
        return self._tenant_id

    @property
    def membership_id(self) -> MembershipId:
        return self._membership_id

    @property
    def user_name(self) -> str:
        return self._user_name

    @property
    def external_id(self) -> str | None:
        return self._external_id

    @property
    def active(self) -> bool:
        return self._active

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
        user_name: str,
        external_id: str | None,
        active: bool,
        at: datetime,
    ) -> None:
        if self.status is ProvisioningResourceStatus.DELETED:
            raise ProvisioningManagedStateConflict("Deleted provisioning resources are immutable")
        self._require_utc(at, "at")
        user_name = user_name.strip()
        if not user_name:
            raise InvalidProvisioningResource("user_name must not be empty")
        self._user_name = user_name
        self._external_id = _optional_text(external_id)
        self._active = active
        self._touch(at)

    def delete(self, *, at: datetime) -> None:
        if self.status is ProvisioningResourceStatus.DELETED:
            return
        self._require_utc(at, "at")
        self._status = ProvisioningResourceStatus.DELETED
        self._active = False
        self._deleted_at = at
        self._touch(at)

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise InvalidProvisioningResource(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProvisioningUser):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
