import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import inspect

from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyIdentityRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
    drop_schema,
)

NOW = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)


def _assert_no_pyiamkit_tables(engine) -> None:
    tables = inspect(engine).get_table_names()
    assert not any(name.startswith("iam_") for name in tables)


def _assert_identity_survives_repeated_bootstrap(engine) -> None:
    create_schema(engine)
    factory = create_session_factory(engine)
    identity = Identity.create_user(display_name="RC Bootstrap", created_at=NOW)

    with factory.begin() as session:
        SqlAlchemyIdentityRepository(session).save(identity)

    create_schema(engine)

    with factory() as session:
        loaded = SqlAlchemyIdentityRepository(session).get(identity.id)
        assert loaded == identity


@pytest.mark.integration
def test_sqlite_schema_bootstrap_is_idempotent_and_recreatable(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(
        f"sqlite+pysqlite:///{tmp_path / 'production-qualification.db'}"
    )
    try:
        _assert_identity_survives_repeated_bootstrap(engine)

        drop_schema(engine)
        _assert_no_pyiamkit_tables(engine)

        create_schema(engine)
        tables = set(inspect(engine).get_table_names())
        assert "iam_identities" in tables
        assert "iam_tenants" in tables
        assert "iam_role_bindings" in tables
        assert "iam_audit_events" in tables
        assert "iam_outbox_events" in tables
    finally:
        drop_schema(engine)
        engine.dispose()


@pytest.mark.integration
def test_postgresql_schema_bootstrap_is_idempotent_and_recreatable() -> None:
    database_url = os.getenv("PYIAMKIT_TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("PYIAMKIT_TEST_DATABASE_URL is not configured")

    engine = create_sqlalchemy_engine(database_url)
    try:
        drop_schema(engine)
        _assert_identity_survives_repeated_bootstrap(engine)

        drop_schema(engine)
        _assert_no_pyiamkit_tables(engine)

        create_schema(engine)
        tables = set(inspect(engine).get_table_names())
        assert "iam_identities" in tables
        assert "iam_security_state" in tables
        assert "iam_outbox_events" in tables
    finally:
        drop_schema(engine)
        engine.dispose()
