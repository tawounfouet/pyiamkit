"""SQLAlchemy engine, schema and session bootstrap helpers."""

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .schema import metadata


def create_sqlalchemy_engine(
    url: str,
    *,
    echo: bool = False,
) -> Engine:
    """Create a SQLAlchemy engine without coupling domain code to SQLAlchemy."""

    engine = create_engine(url, echo=echo, future=True, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_schema(engine: Engine) -> None:
    """Create the alpha persistence schema.

    Production deployments should eventually use migrations. ``create_schema``
    exists for bootstrap, tests and local development during the 0.3.x line.
    """

    metadata.create_all(engine)


def drop_schema(engine: Engine) -> None:
    """Drop all PyIAMKit SQLAlchemy tables."""

    metadata.drop_all(engine)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return an explicit transaction-oriented Session factory."""

    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
