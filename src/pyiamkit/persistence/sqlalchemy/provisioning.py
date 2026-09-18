"""SQLAlchemy persistence for tenant-scoped provisioning resources."""

from sqlalchemy import func, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from pyiamkit.identity import IdentityId
from pyiamkit.provisioning import (
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
)
from pyiamkit.tenancy import MembershipId, TenantId

from .common import optional_utc_from_db, upsert, utc_from_db, uuid_from_db
from .schema import provisioning_user_table


class SqlAlchemyProvisioningUserRepository:
    """Database-backed SCIM/provisioning resource mapping repository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, resource_id: ProvisioningResourceId) -> ProvisioningUser | None:
        row = (
            self._session.execute(
                select(provisioning_user_table).where(
                    provisioning_user_table.c.id == resource_id.value
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _resource_from_row(row)

    def save(self, resource: ProvisioningUser) -> None:
        upsert(
            self._session,
            provisioning_user_table,
            provisioning_user_table.c.id == resource.id.value,
            {
                "id": resource.id.value,
                "version": resource.version,
                "source_id": resource.source_id,
                "identity_id": resource.identity_id.value,
                "tenant_id": resource.tenant_id.value,
                "membership_id": resource.membership_id.value,
                "user_name": resource.user_name,
                "external_id": resource.external_id,
                "active": resource.active,
                "status": resource.status.value,
                "created_at": resource.created_at,
                "updated_at": resource.updated_at,
                "deleted_at": resource.deleted_at,
            },
        )

    def find_by_external_id(
        self,
        source_id: str,
        external_id: str,
    ) -> ProvisioningUser | None:
        row = (
            self._session.execute(
                select(provisioning_user_table).where(
                    provisioning_user_table.c.source_id == source_id.strip(),
                    provisioning_user_table.c.external_id == external_id.strip(),
                    provisioning_user_table.c.status
                    == ProvisioningResourceStatus.ACTIVE.value,
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _resource_from_row(row)

    def find_by_user_name(
        self,
        source_id: str,
        user_name: str,
    ) -> ProvisioningUser | None:
        row = (
            self._session.execute(
                select(provisioning_user_table).where(
                    provisioning_user_table.c.source_id == source_id.strip(),
                    func.lower(provisioning_user_table.c.user_name)
                    == user_name.strip().lower(),
                    provisioning_user_table.c.status
                    == ProvisioningResourceStatus.ACTIVE.value,
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _resource_from_row(row)

    def list_for_source(
        self,
        source_id: str,
        tenant_id: TenantId,
    ) -> tuple[ProvisioningUser, ...]:
        rows = (
            self._session.execute(
                select(provisioning_user_table)
                .where(
                    provisioning_user_table.c.source_id == source_id.strip(),
                    provisioning_user_table.c.tenant_id == tenant_id.value,
                    provisioning_user_table.c.status
                    == ProvisioningResourceStatus.ACTIVE.value,
                )
                .order_by(
                    func.lower(provisioning_user_table.c.user_name),
                    provisioning_user_table.c.id,
                )
            )
            .mappings()
            .all()
        )
        return tuple(_resource_from_row(row) for row in rows)


def _resource_from_row(row: RowMapping) -> ProvisioningUser:
    return ProvisioningUser._rehydrate(
        resource_id=ProvisioningResourceId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        source_id=str(row["source_id"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        tenant_id=TenantId(uuid_from_db(row["tenant_id"])),
        membership_id=MembershipId(uuid_from_db(row["membership_id"])),
        user_name=str(row["user_name"]),
        external_id=None if row["external_id"] is None else str(row["external_id"]),
        active=bool(row["active"]),
        status=ProvisioningResourceStatus(str(row["status"])),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        deleted_at=optional_utc_from_db(row["deleted_at"]),
    )
