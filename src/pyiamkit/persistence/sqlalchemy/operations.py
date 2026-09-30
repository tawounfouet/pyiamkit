"""SQLAlchemy adapter for authoritative security-state versions."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, tuple_
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    SecurityStateReader,
    SecurityStateStamp,
    SecurityStateWriter,
    StateVersion,
)
from pyiamkit.tenancy import TenantId

from .schema import security_state_table

_GLOBAL_SCOPE = "global"
_RUNTIME_GENERATION = "runtime_generation"
_IDENTITY = "identity"
_TENANT = "tenant"
_MEMBERSHIP = "membership"
_SUBJECT_AUTHORIZATION = "subject_authorization"
_TENANT_AUTHORIZATION = "tenant_authorization"
_GLOBAL_AUTHORIZATION = "global_authorization"
_GOVERNANCE = "governance"
_AUTHENTICATION = "authentication"


class SqlAlchemySecurityStateStore(SecurityStateReader, SecurityStateWriter):
    """Durable security-state store using caller-owned SQLAlchemy transactions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp:
        subject_scope = self._subject_tenant_scope(identity_id, tenant_id)
        identity_scope = str(identity_id)
        tenant_scope = str(tenant_id)
        keys = (
            (_RUNTIME_GENERATION, _GLOBAL_SCOPE),
            (_IDENTITY, identity_scope),
            (_TENANT, tenant_scope),
            (_MEMBERSHIP, subject_scope),
            (_SUBJECT_AUTHORIZATION, subject_scope),
            (_TENANT_AUTHORIZATION, tenant_scope),
            (_GLOBAL_AUTHORIZATION, _GLOBAL_SCOPE),
            (_GOVERNANCE, tenant_scope),
            (_AUTHENTICATION, identity_scope),
        )
        rows = self._session.execute(
            select(
                security_state_table.c.dimension,
                security_state_table.c.scope_key,
                security_state_table.c.version,
            ).where(
                tuple_(
                    security_state_table.c.dimension,
                    security_state_table.c.scope_key,
                ).in_(keys)
            )
        ).all()
        versions = {
            (str(row.dimension), str(row.scope_key)): StateVersion(int(row.version)) for row in rows
        }

        def version(dimension: str, scope_key: str) -> StateVersion:
            return versions.get((dimension, scope_key), StateVersion(0))

        return SecurityStateStamp(
            runtime_generation=version(_RUNTIME_GENERATION, _GLOBAL_SCOPE),
            identity=version(_IDENTITY, identity_scope),
            tenant=version(_TENANT, tenant_scope),
            membership=version(_MEMBERSHIP, subject_scope),
            subject_authorization=version(_SUBJECT_AUTHORIZATION, subject_scope),
            tenant_authorization=version(_TENANT_AUTHORIZATION, tenant_scope),
            global_authorization=version(_GLOBAL_AUTHORIZATION, _GLOBAL_SCOPE),
            governance=version(_GOVERNANCE, tenant_scope),
            authentication=version(_AUTHENTICATION, identity_scope),
        )

    def bump_runtime_generation(self) -> StateVersion:
        return self._bump(_RUNTIME_GENERATION, _GLOBAL_SCOPE)

    def bump_identity(self, identity_id: IdentityId) -> StateVersion:
        return self._bump(_IDENTITY, str(identity_id))

    def bump_tenant(self, tenant_id: TenantId) -> StateVersion:
        return self._bump(_TENANT, str(tenant_id))

    def bump_membership(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion:
        return self._bump(_MEMBERSHIP, self._subject_tenant_scope(identity_id, tenant_id))

    def bump_subject_authorization(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion:
        return self._bump(
            _SUBJECT_AUTHORIZATION,
            self._subject_tenant_scope(identity_id, tenant_id),
        )

    def bump_tenant_authorization(self, tenant_id: TenantId) -> StateVersion:
        return self._bump(_TENANT_AUTHORIZATION, str(tenant_id))

    def bump_global_authorization(self) -> StateVersion:
        return self._bump(_GLOBAL_AUTHORIZATION, _GLOBAL_SCOPE)

    def bump_governance(self, tenant_id: TenantId) -> StateVersion:
        return self._bump(_GOVERNANCE, str(tenant_id))

    def bump_authentication(self, identity_id: IdentityId) -> StateVersion:
        return self._bump(_AUTHENTICATION, str(identity_id))

    def _bump(self, dimension: str, scope_key: str) -> StateVersion:
        bind = self._session.get_bind()
        dialect = bind.dialect.name
        now = datetime.now(UTC)
        values = {
            "dimension": dimension,
            "scope_key": scope_key,
            "version": 1,
            "updated_at": now,
        }
        statement: Any
        if dialect == "postgresql":
            insert_statement = postgresql_insert(security_state_table).values(**values)
            statement = insert_statement.on_conflict_do_update(
                index_elements=[
                    security_state_table.c.dimension,
                    security_state_table.c.scope_key,
                ],
                set_={
                    "version": security_state_table.c.version + 1,
                    "updated_at": now,
                },
            ).returning(security_state_table.c.version)
        elif dialect == "sqlite":
            insert_statement = sqlite_insert(security_state_table).values(**values)
            statement = insert_statement.on_conflict_do_update(
                index_elements=[
                    security_state_table.c.dimension,
                    security_state_table.c.scope_key,
                ],
                set_={
                    "version": security_state_table.c.version + 1,
                    "updated_at": now,
                },
            ).returning(security_state_table.c.version)
        else:
            raise NotImplementedError(
                "SqlAlchemySecurityStateStore supports PostgreSQL and SQLite."
            )
        persisted = self._session.execute(statement).scalar_one()
        return StateVersion(int(persisted))

    @staticmethod
    def _subject_tenant_scope(identity_id: IdentityId, tenant_id: TenantId) -> str:
        return f"{identity_id}:{tenant_id}"
