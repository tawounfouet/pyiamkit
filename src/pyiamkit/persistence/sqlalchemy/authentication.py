"""SQLAlchemy implementations of Authentication persistence ports."""

from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session as SqlAlchemySession

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Credential,
    CredentialId,
    CredentialStatus,
    CredentialType,
    MfaFactor,
    MfaFactorId,
    MfaFactorStatus,
    MfaFactorType,
    Session,
    SessionId,
    SessionStatus,
)
from pyiamkit.identity import IdentityId

from .common import (
    ensure_json_mapping,
    mapping_from_json,
    optional_utc_from_db,
    upsert,
    utc_from_db,
    uuid_from_db,
)
from .schema import credential_table, mfa_factor_table, session_table


class SqlAlchemyCredentialRepository:
    """Database-backed CredentialRepository with no raw-secret persistence."""

    def __init__(self, session: SqlAlchemySession) -> None:
        self._session = session

    def get(self, credential_id: CredentialId) -> Credential | None:
        row = (
            self._session.execute(
                select(credential_table).where(credential_table.c.id == credential_id.value)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _credential_from_row(row)

    def save(self, credential: Credential) -> None:
        upsert(
            self._session,
            credential_table,
            credential_table.c.id == credential.id.value,
            {
                "id": credential.id.value,
                "version": credential.version,
                "identity_id": credential.identity_id.value,
                "credential_type": credential.type.value,
                "status": credential.status.value,
                "reference": credential.reference,
                "fingerprint": credential.fingerprint,
                "label": credential.label,
                "created_at": credential.created_at,
                "updated_at": credential.updated_at,
                "valid_from": credential.valid_from,
                "valid_until": credential.valid_until,
                "revoked_at": credential.revoked_at,
                "metadata_json": ensure_json_mapping(credential.metadata),
            },
        )

    def find_by_reference(self, reference: str) -> Credential | None:
        normalized = reference.strip()
        row = (
            self._session.execute(
                select(credential_table).where(credential_table.c.reference == normalized)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _credential_from_row(row)

    def find_for_identity(self, identity_id: IdentityId) -> tuple[Credential, ...]:
        rows = (
            self._session.execute(
                select(credential_table)
                .where(credential_table.c.identity_id == identity_id.value)
                .order_by(credential_table.c.created_at, credential_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_credential_from_row(row) for row in rows)

    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Credential, ...]:
        rows = (
            self._session.execute(
                select(credential_table)
                .where(
                    credential_table.c.identity_id == identity_id.value,
                    credential_table.c.status == CredentialStatus.ACTIVE.value,
                    credential_table.c.valid_from <= at,
                    or_(
                        credential_table.c.valid_until.is_(None),
                        credential_table.c.valid_until > at,
                    ),
                )
                .order_by(credential_table.c.created_at, credential_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_credential_from_row(row) for row in rows)


class SqlAlchemyMfaFactorRepository:
    """Database-backed MFA factor repository with opaque secret references only."""

    def __init__(self, session: SqlAlchemySession) -> None:
        self._session = session

    def get(self, factor_id: MfaFactorId) -> MfaFactor | None:
        row = (
            self._session.execute(
                select(mfa_factor_table).where(mfa_factor_table.c.id == factor_id.value)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _mfa_factor_from_row(row)

    def save(self, factor: MfaFactor) -> None:
        upsert(
            self._session,
            mfa_factor_table,
            mfa_factor_table.c.id == factor.id.value,
            {
                "id": factor.id.value,
                "version": factor.version,
                "identity_id": factor.identity_id.value,
                "factor_type": factor.type.value,
                "status": factor.status.value,
                "secret_reference": factor.secret_reference,
                "label": factor.label,
                "created_at": factor.created_at,
                "updated_at": factor.updated_at,
                "activated_at": factor.activated_at,
                "revoked_at": factor.revoked_at,
                "last_verified_at": factor.last_verified_at,
                "last_accepted_counter": factor.last_accepted_counter,
            },
        )

    def find_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        rows = (
            self._session.execute(
                select(mfa_factor_table)
                .where(mfa_factor_table.c.identity_id == identity_id.value)
                .order_by(mfa_factor_table.c.created_at, mfa_factor_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_mfa_factor_from_row(row) for row in rows)

    def find_active_for_identity(self, identity_id: IdentityId) -> tuple[MfaFactor, ...]:
        rows = (
            self._session.execute(
                select(mfa_factor_table)
                .where(
                    mfa_factor_table.c.identity_id == identity_id.value,
                    mfa_factor_table.c.status == MfaFactorStatus.ACTIVE.value,
                )
                .order_by(mfa_factor_table.c.created_at, mfa_factor_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_mfa_factor_from_row(row) for row in rows)


class SqlAlchemySessionRepository:
    """Database-backed SessionRepository."""

    def __init__(self, session: SqlAlchemySession) -> None:
        self._session = session

    def get(self, session_id: SessionId) -> Session | None:
        row = (
            self._session.execute(
                select(session_table).where(session_table.c.id == session_id.value)
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _session_from_row(row)

    def save(self, session: Session) -> None:
        upsert(
            self._session,
            session_table,
            session_table.c.id == session.id.value,
            {
                "id": session.id.value,
                "version": session.version,
                "identity_id": session.identity_id.value,
                "status": session.status.value,
                "authentication_method": session.context.method.value,
                "assurance_level": session.context.assurance_level.value,
                "mfa": session.context.mfa,
                "authenticated_at": session.context.authenticated_at,
                "provider_id": session.context.provider_id,
                "device_id": session.context.device_id,
                "network_zone": session.context.network_zone,
                "mfa_verified_at": session.context.mfa_verified_at,
                "mfa_factor_id": (
                    None
                    if session.context.mfa_factor_id is None
                    else MfaFactorId.parse(session.context.mfa_factor_id).value
                ),
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "expires_at": session.expires_at,
                "last_activity_at": session.last_activity_at,
                "revoked_at": session.revoked_at,
                "revocation_reason": session.revocation_reason,
            },
        )

    def find_for_identity(self, identity_id: IdentityId) -> tuple[Session, ...]:
        rows = (
            self._session.execute(
                select(session_table)
                .where(session_table.c.identity_id == identity_id.value)
                .order_by(session_table.c.created_at, session_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_session_from_row(row) for row in rows)

    def find_active_for_identity(
        self,
        identity_id: IdentityId,
        at: datetime,
    ) -> tuple[Session, ...]:
        rows = (
            self._session.execute(
                select(session_table)
                .where(
                    session_table.c.identity_id == identity_id.value,
                    session_table.c.status == SessionStatus.ACTIVE.value,
                    session_table.c.expires_at > at,
                )
                .order_by(session_table.c.created_at, session_table.c.id)
            )
            .mappings()
            .all()
        )
        return tuple(_session_from_row(row) for row in rows)


def _credential_from_row(row: RowMapping) -> Credential:
    return Credential._rehydrate(
        credential_id=CredentialId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        credential_type=CredentialType(str(row["credential_type"])),
        status=CredentialStatus(str(row["status"])),
        reference=str(row["reference"]),
        fingerprint=None if row["fingerprint"] is None else str(row["fingerprint"]),
        label=None if row["label"] is None else str(row["label"]),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        valid_from=utc_from_db(row["valid_from"]),
        valid_until=optional_utc_from_db(row["valid_until"]),
        revoked_at=optional_utc_from_db(row["revoked_at"]),
        metadata=mapping_from_json(row["metadata_json"]),
    )


def _mfa_factor_from_row(row: RowMapping) -> MfaFactor:
    return MfaFactor._rehydrate(
        factor_id=MfaFactorId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        factor_type=MfaFactorType(str(row["factor_type"])),
        status=MfaFactorStatus(str(row["status"])),
        secret_reference=str(row["secret_reference"]),
        label=None if row["label"] is None else str(row["label"]),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        activated_at=optional_utc_from_db(row["activated_at"]),
        revoked_at=optional_utc_from_db(row["revoked_at"]),
        last_verified_at=optional_utc_from_db(row["last_verified_at"]),
        last_accepted_counter=(
            None
            if row["last_accepted_counter"] is None
            else int(row["last_accepted_counter"])
        ),
    )


def _session_from_row(row: RowMapping) -> Session:
    context = AuthenticationContext(
        method=AuthenticationMethod(str(row["authentication_method"])),
        assurance_level=AssuranceLevel(str(row["assurance_level"])),
        mfa=bool(row["mfa"]),
        authenticated_at=utc_from_db(row["authenticated_at"]),
        provider_id=None if row["provider_id"] is None else str(row["provider_id"]),
        device_id=None if row["device_id"] is None else str(row["device_id"]),
        network_zone=None if row["network_zone"] is None else str(row["network_zone"]),
        mfa_verified_at=optional_utc_from_db(row["mfa_verified_at"]),
        mfa_factor_id=(
            None if row["mfa_factor_id"] is None else str(uuid_from_db(row["mfa_factor_id"]))
        ),
    )
    return Session._rehydrate(
        session_id=SessionId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        status=SessionStatus(str(row["status"])),
        context=context,
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        expires_at=utc_from_db(row["expires_at"]),
        last_activity_at=utc_from_db(row["last_activity_at"]),
        revoked_at=optional_utc_from_db(row["revoked_at"]),
        revocation_reason=(
            None if row["revocation_reason"] is None else str(row["revocation_reason"])
        ),
    )
