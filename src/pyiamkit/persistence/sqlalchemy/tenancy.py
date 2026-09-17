"""SQLAlchemy implementations of Tenancy repository ports."""

from datetime import datetime

from sqlalchemy import select
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


def _tenant_from_row(row: object) -> Tenant:
    mapping = row
    return Tenant._rehydrate(
        tenant_id=TenantId(uuid_from_db(mapping["id"])),  # type: ignore[index]
        version=int(mapping["version"]),  # type: ignore[index]
        name=str(mapping["name"]),  # type: ignore[index]
        slug=str(mapping["slug"]),  # type: ignore[index]
        status=TenantStatus(str(mapping["status"])),  # type: ignore[index]
        created_at=utc_from_db(mapping["created_at"]),  # type: ignore[index]
        updated_at=utc_from_db(mapping["updated_at"]),  # type: ignore[index]
        metadata=mapping_from_json(mapping["metadata_json"]),  # type: ignore[index]
    )


def _membership_from_row(row: object) -> Membership:
    mapping = row
    organization_uuid = optional_uuid_from_db(mapping["organization_id"])  # type: ignore[index]
    return Membership._rehydrate(
        membership_id=MembershipId(uuid_from_db(mapping["id"])),  # type: ignore[index]
        version=int(mapping["version"]),  # type: ignore[index]
        identity_id=IdentityId(uuid_from_db(mapping["identity_id"])),  # type: ignore[index]
        tenant_id=TenantId(uuid_from_db(mapping["tenant_id"])),  # type: ignore[index]
        organization_id=None if organization_uuid is None else OrganizationId(organization_uuid),
        status=MembershipStatus(str(mapping["status"])),  # type: ignore[index]
        source=str(mapping["source"]),  # type: ignore[index]
        created_at=utc_from_db(mapping["created_at"]),  # type: ignore[index]
        updated_at=utc_from_db(mapping["updated_at"]),  # type: ignore[index]
        valid_from=utc_from_db(mapping["valid_from"]),  # type: ignore[index]
        valid_until=optional_utc_from_db(mapping["valid_until"]),  # type: ignore[index]
    )
