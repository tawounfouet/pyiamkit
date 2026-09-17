"""SQLAlchemy implementation of the Identity repository port."""

from datetime import datetime

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from pyiamkit.identity import (
    EmailAddress,
    Identity,
    IdentityId,
    IdentityStatus,
    IdentityType,
    ServiceAccount,
    User,
)
from pyiamkit.identity.domain.entities.external_identity_link import ExternalIdentityLink

from .common import (
    ensure_json_mapping,
    mapping_from_json,
    optional_utc_from_db,
    upsert,
    utc_from_db,
    uuid_from_db,
)
from .schema import identity_external_link_table, identity_table


class SqlAlchemyIdentityRepository:
    """Database-backed IdentityRepository using an injected SQLAlchemy Session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, identity_id: IdentityId) -> Identity | None:
        row = (
            self._session.execute(
                select(identity_table).where(identity_table.c.id == identity_id.value)
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None

        links = (
            self._session.execute(
                select(identity_external_link_table)
                .where(identity_external_link_table.c.identity_id == identity_id.value)
                .order_by(
                    identity_external_link_table.c.linked_at,
                    identity_external_link_table.c.provider_id,
                    identity_external_link_table.c.external_subject,
                )
            )
            .mappings()
            .all()
        )
        identity_type = IdentityType(str(row["identity_type"]))
        profile = _profile_from_json(identity_type, mapping_from_json(row["profile"]))
        return Identity._rehydrate(
            identity_id=IdentityId(uuid_from_db(row["id"])),
            version=int(row["version"]),
            identity_type=identity_type,
            status=IdentityStatus(str(row["status"])),
            display_name=str(row["display_name"]),
            profile=profile,
            created_at=utc_from_db(row["created_at"]),
            updated_at=utc_from_db(row["updated_at"]),
            activated_at=optional_utc_from_db(row["activated_at"]),
            suspended_at=optional_utc_from_db(row["suspended_at"]),
            disabled_at=optional_utc_from_db(row["disabled_at"]),
            archived_at=optional_utc_from_db(row["archived_at"]),
            external_links=tuple(
                ExternalIdentityLink(
                    provider_id=str(link["provider_id"]),
                    external_subject=str(link["external_subject"]),
                    linked_at=utc_from_db(link["linked_at"]),
                )
                for link in links
            ),
            metadata=mapping_from_json(row["metadata_json"]),
        )

    def save(self, identity: Identity) -> None:
        values = {
            "id": identity.id.value,
            "version": identity.version,
            "identity_type": identity.type.value,
            "status": identity.status.value,
            "display_name": identity.display_name,
            "profile": _profile_to_json(identity.profile),
            "created_at": identity.created_at,
            "updated_at": identity.updated_at,
            "activated_at": identity.activated_at,
            "suspended_at": identity.suspended_at,
            "disabled_at": identity.disabled_at,
            "archived_at": identity.archived_at,
            "metadata_json": ensure_json_mapping(identity.metadata),
        }
        upsert(
            self._session,
            identity_table,
            identity_table.c.id == identity.id.value,
            values,
        )
        self._session.execute(
            delete(identity_external_link_table).where(
                identity_external_link_table.c.identity_id == identity.id.value
            )
        )
        if identity.external_links:
            self._session.execute(
                insert(identity_external_link_table),
                [
                    {
                        "identity_id": identity.id.value,
                        "provider_id": link.provider_id,
                        "external_subject": link.external_subject,
                        "linked_at": link.linked_at,
                    }
                    for link in identity.external_links
                ],
            )

    def exists(self, identity_id: IdentityId) -> bool:
        return (
            self._session.execute(
                select(identity_table.c.id).where(identity_table.c.id == identity_id.value)
            ).scalar_one_or_none()
            is not None
        )

    def find_by_external_subject(
        self,
        provider_id: str,
        external_subject: str,
    ) -> Identity | None:
        identity_id = self._session.execute(
            select(identity_external_link_table.c.identity_id).where(
                identity_external_link_table.c.provider_id == provider_id.strip(),
                identity_external_link_table.c.external_subject == external_subject.strip(),
            )
        ).scalar_one_or_none()
        if identity_id is None:
            return None
        return self.get(IdentityId(uuid_from_db(identity_id)))


def _profile_to_json(profile: User | ServiceAccount) -> dict[str, object]:
    if isinstance(profile, User):
        return ensure_json_mapping(
            {
                "kind": "user",
                "primary_email": (
                    None if profile.primary_email is None else str(profile.primary_email)
                ),
                "email_verified": profile.email_verified,
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "locale": profile.locale,
                "timezone": profile.timezone,
            }
        )
    return ensure_json_mapping(
        {
            "kind": "service_account",
            "name": profile.name,
            "owner_identity_id": str(profile.owner_identity_id),
            "purpose": profile.purpose,
            "environment": profile.environment,
            "expires_at": None if profile.expires_at is None else profile.expires_at.isoformat(),
        }
    )


def _profile_from_json(
    identity_type: IdentityType,
    payload: dict[str, object],
) -> User | ServiceAccount:
    if identity_type is IdentityType.USER:
        email_value = payload.get("primary_email")
        return User(
            primary_email=None if email_value is None else EmailAddress.parse(str(email_value)),
            email_verified=bool(payload.get("email_verified", False)),
            first_name=_optional_text(payload.get("first_name")),
            last_name=_optional_text(payload.get("last_name")),
            locale=_optional_text(payload.get("locale")),
            timezone=_optional_text(payload.get("timezone")),
        )

    expires_value = payload.get("expires_at")
    expires_at: datetime | None = None
    if expires_value is not None:
        expires_at = datetime.fromisoformat(str(expires_value))
    return ServiceAccount(
        name=str(payload["name"]),
        owner_identity_id=IdentityId.parse(str(payload["owner_identity_id"])),
        purpose=str(payload["purpose"]),
        environment=_optional_text(payload.get("environment")),
        expires_at=expires_at,
    )


def _optional_text(value: object | None) -> str | None:
    return None if value is None else str(value)
