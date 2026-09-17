"""SQLAlchemy implementations of Tenancy repository ports."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import (
    Membership,
    MembershipId,
    MembershipStatus,
    OrganizationId,
    Tenant,
    TenantId,
    TenantStatus,
)

from .common import (
    ensure_json_mapping,
    mapping_from_json,
    optional_utc_from_db,
    optional_uuid_from_db,
    utc_from_db,
    uuid_from_db,
    upsert,
)
from .schema import membership_table, tenant_table


class SqlAlchemyTenantRepository:
    """Database-backed TenantRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, tenant_id: TenantId) -> Tenant | None:
        row = self._session.execute(
            select(tenant_table).where(tenant_table.c.id == tenant_id.value)
        ).mappings().one_or_none()
        return None if row is None else _tenant_from_row(row)

    def save(self, tenant: Tenant) -> None:
        upsert(
            self._session,
            tenant_table,
            tenant_table.c.id == tenant.id.value,
            {
                "id": tenant.id.value,
                "version": tenant.version,
                "name": tenant.name,
                "slug": tenant.slug,
                "status": tenant.status.value,
                "created_at": tenant.created_at,
                "updated_at": tenant.updated_at,
                "metadata_json": ensure_json_mapping(tenant.metadata),
            },
        )

    def find_by_slug(self, slug: str) -> Tenant | None:
        row = self._session.execute(
            select(tenant_table).where(tenant_table.c.slug == slug.strip().lower())
        ).mappings().one_or_none()
        return None if row is None else _tenant_from_row(row)


class SqlAlchemyMembershipRepository:
    """Database-backed MembershipRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, membership_id: MembershipId) -> Membership | None:
        row = self._session.execute(
            select(membership_table).where(membership_table.c.id == membership_id.value)
        ).mappings().one_or_none()
        return None if row is None else _membership_from_row(row)

    def save(self, membership: Membership) -> None:
        upsert(
            self._session,
            membership_table,
            membership_table.c.id == membership.id.value,
            {
                "id": membership.id.value,
                "version": membership.version,
                "identity_id": membership.identity_id.value,
                "tenant_id": membership.tenant_id.value,
                "organization_id": (
                    None if membership.organization_id is None else membership.organization_id.value
                ),
                "status": membership.status.value,
                "source": membership.source,
                "created_at": membership.created_at,
                "updated_at": membership.updated_at,
                "valid_from": membership.valid_from,
                "valid_until": membership.valid_until,
            },
        )

    def find(self, identity_id: IdentityId, tenant_id: TenantId) -> Membership | None:
        row = self._session.execute(
            select(membership_table).where(
                membership_table.c.identity_id == identity_id.value,
                membership_table.c.tenant_id == tenant_id.value,
            )
        ).mappings().one_or_none()
        return None if row is None else _membership_from_row(row)

    def find_active(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
        at: datetime,
    ) -> Membership | None:
        membership = self.find(identity_id, tenant_id)
        if membership is None or not membership.is_active(at=at):
            return None
        return membership


def _tenant_from_row(row: RowMapping) -> Tenant:
    return Tenant._rehydrate(
        tenant_id=TenantId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        name=str(row["name"]),
        slug=str(row["slug"]),
        status=TenantStatus(str(row["status"])),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        metadata=mapping_from_json(row["metadata_json"]),
    )


def _membership_from_row(row: RowMapping) -> Membership:
    organization_uuid = optional_uuid_from_db(row["organization_id"])
    return Membership._rehydrate(
        membership_id=MembershipId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        tenant_id=TenantId(uuid_from_db(row["tenant_id"])),
        organization_id=None if organization_uuid is None else OrganizationId(organization_uuid),
        status=MembershipStatus(str(row["status"])),
        source=str(row["source"]),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        valid_from=utc_from_db(row["valid_from"]),
        valid_until=optional_utc_from_db(row["valid_until"]),
    )
