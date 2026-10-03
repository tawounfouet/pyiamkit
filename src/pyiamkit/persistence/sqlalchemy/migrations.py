"""Versioned SQLAlchemy schema migration baseline for production deployments."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import (
    Column,
    DateTime,
    Engine,
    MetaData,
    String,
    Table,
    delete,
    insert,
    inspect,
    select,
)

from ..errors import PersistenceError
from .schema import metadata

BASELINE_SCHEMA_VERSION = "0001_0_5_0rc1_baseline"
_MIGRATION_TABLE_NAME = "iam_schema_migrations"

_migration_metadata = MetaData()
_schema_migration_table = Table(
    _MIGRATION_TABLE_NAME,
    _migration_metadata,
    Column("version", String(128), primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False),
)


class SchemaMigrationError(PersistenceError):
    """Raised when schema state cannot be migrated safely."""

    code = "SCHEMA_MIGRATION_ERROR"


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """Result of applying the current PyIAMKit schema baseline."""

    version: str
    applied: bool
    created_schema: bool
    adopted_existing_schema: bool


def current_schema_version(engine: Engine) -> str | None:
    """Return the applied schema version, validating migration history."""

    if _MIGRATION_TABLE_NAME not in set(inspect(engine).get_table_names()):
        return None

    with engine.connect() as connection:
        versions = tuple(
            connection.execute(
                select(_schema_migration_table.c.version).order_by(
                    _schema_migration_table.c.applied_at,
                    _schema_migration_table.c.version,
                )
            ).scalars()
        )

    if not versions:
        return None
    _validate_known_versions(versions)
    return cast(str, versions[-1])


def migrate_schema(engine: Engine) -> MigrationResult:
    """Create or adopt the current schema and stamp the RC1 migration baseline.

    Existing pre-RC databases created from the current SQLAlchemy metadata are
    adopted without destructive DDL. A partially present PyIAMKit schema fails
    closed because automatically guessing how to repair it could hide data loss.
    """

    expected_tables = set(metadata.tables)
    created_schema = False
    adopted_existing_schema = False

    with engine.begin() as connection:
        actual_tables = set(inspect(connection).get_table_names())
        if _MIGRATION_TABLE_NAME in actual_tables:
            existing_versions = tuple(
                connection.execute(
                    select(_schema_migration_table.c.version).order_by(
                        _schema_migration_table.c.applied_at,
                        _schema_migration_table.c.version,
                    )
                ).scalars()
            )
            _validate_known_versions(existing_versions)

        present_expected = expected_tables & actual_tables

        if present_expected and present_expected != expected_tables:
            missing = ", ".join(sorted(expected_tables - present_expected))
            raise SchemaMigrationError(
                "Partial PyIAMKit schema detected; refusing baseline adoption. "
                f"Missing tables: {missing}"
            )

        if not present_expected:
            metadata.create_all(connection)
            created_schema = True
        else:
            adopted_existing_schema = True

        _migration_metadata.create_all(connection)
        versions = tuple(
            connection.execute(
                select(_schema_migration_table.c.version).order_by(
                    _schema_migration_table.c.applied_at,
                    _schema_migration_table.c.version,
                )
            ).scalars()
        )
        _validate_known_versions(versions)

        if BASELINE_SCHEMA_VERSION in versions:
            return MigrationResult(
                version=BASELINE_SCHEMA_VERSION,
                applied=False,
                created_schema=False,
                adopted_existing_schema=adopted_existing_schema,
            )

        connection.execute(
            insert(_schema_migration_table).values(
                version=BASELINE_SCHEMA_VERSION,
                applied_at=datetime.now(UTC),
            )
        )

    return MigrationResult(
        version=BASELINE_SCHEMA_VERSION,
        applied=True,
        created_schema=created_schema,
        adopted_existing_schema=adopted_existing_schema,
    )


def rollback_schema_baseline(engine: Engine) -> bool:
    """Remove only the RC1 stamp while preserving IAM data and business tables.

    RC1 introduces migration bookkeeping but no destructive schema change relative
    to 0.5.0b2. Rollback is therefore a non-destructive unstamp so the previous
    application release can continue using the same database schema.
    """

    if _MIGRATION_TABLE_NAME not in set(inspect(engine).get_table_names()):
        return False

    with engine.begin() as connection:
        versions = tuple(
            connection.execute(
                select(_schema_migration_table.c.version).order_by(
                    _schema_migration_table.c.applied_at,
                    _schema_migration_table.c.version,
                )
            ).scalars()
        )
        _validate_known_versions(versions)
        if BASELINE_SCHEMA_VERSION not in versions:
            return False
        result = connection.execute(
            delete(_schema_migration_table).where(
                _schema_migration_table.c.version == BASELINE_SCHEMA_VERSION
            )
        )
        return bool(result.rowcount)


def drop_migration_history(engine: Engine) -> None:
    """Drop only migration bookkeeping for tests and local reset helpers."""

    _migration_metadata.drop_all(engine)


def _validate_known_versions(versions: tuple[str, ...]) -> None:
    unknown = tuple(version for version in versions if version != BASELINE_SCHEMA_VERSION)
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise SchemaMigrationError(f"Unknown PyIAMKit schema migration version(s): {joined}")
