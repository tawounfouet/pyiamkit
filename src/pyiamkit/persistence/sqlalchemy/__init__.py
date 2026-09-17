"""SQLAlchemy persistence adapter bundle.

Install with ``pyiamkit[sqlalchemy]`` for SQLite/SQLAlchemy usage or
``pyiamkit[postgres]`` for PostgreSQL with psycopg.
"""

from .audit import SqlAlchemyAuditRepository
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
    "SqlAlchemyIdentityRepository",
    "SqlAlchemyMembershipRepository",
    "SqlAlchemyPermissionCatalogRepository",
    "SqlAlchemyRoleBindingRepository",
    "SqlAlchemyRoleRepository",
    "SqlAlchemySoDRuleRepository",
    "SqlAlchemyTenantRepository",
    "create_schema",
    "create_session_factory",
    "create_sqlalchemy_engine",
    "drop_schema",
]
