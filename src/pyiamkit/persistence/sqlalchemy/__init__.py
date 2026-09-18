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
from .tenancy import SqlAlchemyMembershipRepository, SqlAlchemyTenantRepository

__all__ = [
    "SqlAlchemyAuditRepository",
    "SqlAlchemyConstraintRepository",
    "SqlAlchemyCredentialRepository",
    "SqlAlchemyIdentityRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyMfaFactorRepository",
    "SqlAlchemyPermissionCatalogRepository",
    "SqlAlchemyRoleBindingRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemySessionRepository",
    "SqlAlchemySoDRuleRepository",
    "SqlAlchemyTenantRepository",
    "create_schema",
    "create_session_factory",
    "create_sqlalchemy_engine",
    "drop_schema",
]
