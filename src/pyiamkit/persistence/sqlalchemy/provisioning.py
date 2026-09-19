"""SQLAlchemy persistence for tenant-scoped provisioning resources."""

from sqlalchemy import delete, func, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from pyiamkit.identity import IdentityId
from pyiamkit.provisioning import (
    ProvisioningGroup,
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
)
from pyiamkit.tenancy import MembershipId, TenantId

from .common import optional_utc_from_db, upsert, utc_from_db, uuid_from_db
from .schema import (
    provisioning_group_member_table,
    provisioning_group_table,
    provisioning_user_table,
)


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
                    provisioning_user_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
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
                    func.lower(provisioning_user_table.c.user_name) == user_name.strip().lower(),
                    provisioning_user_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
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
                    provisioning_user_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
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


class SqlAlchemyProvisioningGroupRepository:
    """Database-backed SCIM Group resource repository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, resource_id: ProvisioningResourceId) -> ProvisioningGroup | None:
        row = (
            self._session.execute(
                select(provisioning_group_table).where(
                    provisioning_group_table.c.id == resource_id.value
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        return _group_from_row(row, self._member_ids(resource_id))

    def save(self, resource: ProvisioningGroup) -> None:
        upsert(
            self._session,
            provisioning_group_table,
            provisioning_group_table.c.id == resource.id.value,
            {
                "id": resource.id.value,
                "version": resource.version,
                "source_id": resource.source_id,
                "tenant_id": resource.tenant_id.value,
                "display_name": resource.display_name,
                "external_id": resource.external_id,
                "status": resource.status.value,
                "created_at": resource.created_at,
                "updated_at": resource.updated_at,
                "deleted_at": resource.deleted_at,
            },
        )
        self._session.execute(
            delete(provisioning_group_member_table).where(
                provisioning_group_member_table.c.group_id == resource.id.value
            )
        )
        if resource.member_ids:
            self._session.execute(
                provisioning_group_member_table.insert(),
                [
                    {
                        "group_id": resource.id.value,
                        "member_resource_id": member_id.value,
                    }
                    for member_id in resource.member_ids
                ],
            )

    def find_by_external_id(
        self,
        source_id: str,
        external_id: str,
    ) -> ProvisioningGroup | None:
        row = (
            self._session.execute(
                select(provisioning_group_table).where(
                    provisioning_group_table.c.source_id == source_id.strip(),
                    provisioning_group_table.c.external_id == external_id.strip(),
                    provisioning_group_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        resource_id = ProvisioningResourceId(uuid_from_db(row["id"]))
        return _group_from_row(row, self._member_ids(resource_id))

    def find_by_display_name(
        self,
        source_id: str,
        display_name: str,
    ) -> ProvisioningGroup | None:
        row = (
            self._session.execute(
                select(provisioning_group_table).where(
                    provisioning_group_table.c.source_id == source_id.strip(),
                    func.lower(provisioning_group_table.c.display_name)
                    == display_name.strip().lower(),
                    provisioning_group_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        resource_id = ProvisioningResourceId(uuid_from_db(row["id"]))
        return _group_from_row(row, self._member_ids(resource_id))

    def list_for_source(
        self,
        source_id: str,
        tenant_id: TenantId,
    ) -> tuple[ProvisioningGroup, ...]:
        rows = (
            self._session.execute(
                select(provisioning_group_table)
                .where(
                    provisioning_group_table.c.source_id == source_id.strip(),
                    provisioning_group_table.c.tenant_id == tenant_id.value,
                    provisioning_group_table.c.status == ProvisioningResourceStatus.ACTIVE.value,
                )
                .order_by(
                    func.lower(provisioning_group_table.c.display_name),
                    provisioning_group_table.c.id,
                )
            )
            .mappings()
            .all()
        )
        resources: list[ProvisioningGroup] = []
        for row in rows:
            resource_id = ProvisioningResourceId(uuid_from_db(row["id"]))
            resources.append(_group_from_row(row, self._member_ids(resource_id)))
        return tuple(resources)

    def _member_ids(
        self,
        resource_id: ProvisioningResourceId,
    ) -> tuple[ProvisioningResourceId, ...]:
        rows = self._session.execute(
            select(provisioning_group_member_table.c.member_resource_id)
            .where(provisioning_group_member_table.c.group_id == resource_id.value)
            .order_by(provisioning_group_member_table.c.member_resource_id)
        ).all()
        return tuple(ProvisioningResourceId(uuid_from_db(row[0])) for row in rows)


def _group_from_row(
    row: RowMapping,
    member_ids: tuple[ProvisioningResourceId, ...],
) -> ProvisioningGroup:
    return ProvisioningGroup._rehydrate(
        resource_id=ProvisioningResourceId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        source_id=str(row["source_id"]),
        tenant_id=TenantId(uuid_from_db(row["tenant_id"])),
        display_name=str(row["display_name"]),
        member_ids=member_ids,
        status=ProvisioningResourceStatus(str(row["status"])),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        external_id=None if row["external_id"] is None else str(row["external_id"]),
        deleted_at=optional_utc_from_db(row["deleted_at"]),
    )
