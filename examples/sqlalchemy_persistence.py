"""Minimal SQLAlchemy persistence example using SQLite."""

from datetime import UTC, datetime

from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyIdentityRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)

now = datetime.now(UTC)
engine = create_sqlalchemy_engine("sqlite+pysqlite:///:memory:")
create_schema(engine)
factory = create_session_factory(engine)

with factory.begin() as session:
    repository = SqlAlchemyIdentityRepository(session)
    identity = Identity.create_user(display_name="Alice", created_at=now)
    identity.pull_events()
    identity.activate(at=now)
    identity.pull_events()
    repository.save(identity)
    identity_id = identity.id

with factory() as session:
    persisted = SqlAlchemyIdentityRepository(session).get(identity_id)
    assert persisted is not None
    print(persisted.id, persisted.status.value)

engine.dispose()
