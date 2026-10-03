"""SQLAlchemy persistence adapter bundle.

Install with ``pyiamkit[sqlalchemy]`` for SQLite/SQLAlchemy usage or
``pyiamkit[postgres]`` for PostgreSQL with psycopg.
"""

from .audit import SqlAlchemyAuditRepository
from .authentication import (
    SqlAlchemyCredentialRepository,
    SqlAlchemyMfaFactorRepository,
    SqlAlchemySessionRepository,
)
from .authorization import (
    SqlAlchemyConstraintRepository,
    SqlAlchemyPermissionCatalogRepository,
    SqlAlchemyRoleBindingRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemySoDRuleRepository,
)
from .database import (
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
    drop_schema,
)
from .identity import SqlAlchemyIdentityRepository
from .migrations import (
    BASELINE_SCHEMA_VERSION,
    MigrationResult,
    SchemaMigrationError,
    current_schema_version,
    migrate_schema,
    rollback_schema_baseline,
)
from .operations import SqlAlchemySecurityStateStore
from .outbox import SqlAlchemyAuditOutboxWriter, SqlAlchemyOutboxRepository
from .provisioning import (
    SqlAlchemyProvisioningGroupRepository,
    SqlAlchemyProvisioningUserRepository,
)
from .tenancy import SqlAlchemyMembershipRepository, SqlAlchemyTenantRepository

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "MigrationResult",
    "SchemaMigrationError",
    "SqlAlchemyAuditOutboxWriter",
    "SqlAlchemyAuditRepository",
    "SqlAlchemyConstraintRepository",
    "SqlAlchemyCredentialRepository",
    "SqlAlchemyIdentityRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyMfaFactorRepository",
    "SqlAlchemyOutboxRepository",
    "SqlAlchemyPermissionCatalogRepository",
    "SqlAlchemyProvisioningGroupRepository",
    "SqlAlchemyProvisioningUserRepository",
    "SqlAlchemyRoleBindingRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemySecurityStateStore",
    "SqlAlchemySessionRepository",
    "SqlAlchemySoDRuleRepository",
    "SqlAlchemyTenantRepository",
    "create_schema",
    "current_schema_version",
    "create_session_factory",
    "create_sqlalchemy_engine",
    "drop_schema",
    "migrate_schema",
    "rollback_schema_baseline",
]
