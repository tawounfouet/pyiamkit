import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Column, DateTime, MetaData, String, Table, inspect

from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    BASELINE_SCHEMA_VERSION,
    SchemaMigrationError,
    SqlAlchemyIdentityRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
    current_schema_version,
    drop_schema,
    migrate_schema,
    rollback_schema_baseline,
)

NOW = datetime(2026, 10, 3, 10, 30, tzinfo=UTC)

pytestmark = pytest.mark.integration


def _assert_legacy_schema_adoption_preserves_identity(engine) -> None:
    create_schema(engine)
    factory = create_session_factory(engine)
    identity = Identity.create_user(display_name="Legacy 0.5.0b2", created_at=NOW)

    with factory.begin() as session:
        SqlAlchemyIdentityRepository(session).save(identity)

    assert current_schema_version(engine) is None

    result = migrate_schema(engine)

    assert result.version == BASELINE_SCHEMA_VERSION
    assert result.applied is True
    assert result.created_schema is False
    assert result.adopted_existing_schema is True
    assert current_schema_version(engine) == BASELINE_SCHEMA_VERSION

    with factory() as session:
        assert SqlAlchemyIdentityRepository(session).get(identity.id) == identity

    assert rollback_schema_baseline(engine) is True
    assert current_schema_version(engine) is None

    with factory() as session:
        assert SqlAlchemyIdentityRepository(session).get(identity.id) == identity

    reapplied = migrate_schema(engine)
    assert reapplied.applied is True
    assert reapplied.adopted_existing_schema is True
    assert current_schema_version(engine) == BASELINE_SCHEMA_VERSION


def test_sqlite_migration_creates_empty_schema_and_is_idempotent(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'migration-empty.db'}")
    try:
        assert current_schema_version(engine) is None

        first = migrate_schema(engine)
        second = migrate_schema(engine)

        assert first.applied is True
        assert first.created_schema is True
        assert first.adopted_existing_schema is False
        assert second.applied is False
        assert second.created_schema is False
        assert second.adopted_existing_schema is True
        assert current_schema_version(engine) == BASELINE_SCHEMA_VERSION

        tables = set(inspect(engine).get_table_names())
        assert "iam_schema_migrations" in tables
        assert "iam_identities" in tables
        assert "iam_audit_events" in tables
        assert "iam_outbox_events" in tables
    finally:
        drop_schema(engine)
        engine.dispose()


def test_sqlite_adopts_0_5_0b2_compatible_schema_without_data_loss(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'migration-adopt.db'}")
    try:
        _assert_legacy_schema_adoption_preserves_identity(engine)
    finally:
        drop_schema(engine)
        engine.dispose()


def test_sqlite_partial_schema_fails_closed_without_stamp(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'migration-partial.db'}")
    partial = MetaData()
    Table(
        "iam_identities",
        partial,
        Column("id", String(36), primary_key=True),
    )
    partial.create_all(engine)

    try:
        with pytest.raises(SchemaMigrationError, match="Partial PyIAMKit schema"):
            migrate_schema(engine)

        assert current_schema_version(engine) is None
        assert "iam_schema_migrations" not in set(inspect(engine).get_table_names())
    finally:
        partial.drop_all(engine)
        engine.dispose()


def test_sqlite_unknown_migration_history_fails_before_business_schema_ddl(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'migration-unknown.db'}")
    ledger = MetaData()
    migration_table = Table(
        "iam_schema_migrations",
        ledger,
        Column("version", String(128), primary_key=True),
        Column("applied_at", DateTime(timezone=True), nullable=False),
    )
    ledger.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            migration_table.insert().values(
                version="9999_unknown",
                applied_at=NOW,
            )
        )

    try:
        with pytest.raises(SchemaMigrationError, match="Unknown PyIAMKit schema migration"):
            migrate_schema(engine)

        tables = set(inspect(engine).get_table_names())
        assert "iam_identities" not in tables
        assert "iam_schema_migrations" in tables
    finally:
        ledger.drop_all(engine)
        engine.dispose()


def test_postgresql_adopts_0_5_0b2_compatible_schema_without_data_loss() -> None:
    database_url = os.getenv("PYIAMKIT_TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("PYIAMKIT_TEST_DATABASE_URL is not configured")

    engine = create_sqlalchemy_engine(database_url)
    try:
        drop_schema(engine)
        _assert_legacy_schema_adoption_preserves_identity(engine)
    finally:
        drop_schema(engine)
        engine.dispose()
