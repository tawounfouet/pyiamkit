from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pyiamkit.audit import (
    AuditCategory,
    AuditEvent,
    OutboxEvent,
    OutboxStatus,
)
from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyAuditOutboxWriter,
    SqlAlchemyAuditRepository,
    SqlAlchemyIdentityRepository,
    SqlAlchemyOutboxRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)

NOW = datetime(2026, 10, 2, 14, 45, tzinfo=UTC)


def _audit() -> AuditEvent:
    return AuditEvent(
        category=AuditCategory.SECURITY,
        event_type="IdentityDisabled",
        occurred_at=NOW,
        subject_id="identity-1",
        tenant_id="tenant-1",
        correlation_id="corr-1",
        metadata={"reason": "policy"},
    )


def _outbox() -> OutboxEvent:
    return OutboxEvent(
        event_type="IdentityDisabled",
        event_version=1,
        aggregate_type="Identity",
        aggregate_id="identity-1",
        aggregate_version=4,
        tenant_id="tenant-1",
        occurred_at=NOW,
        payload={"reason": "policy", "correlation_id": "corr-1"},
    )


def test_sqlalchemy_outbox_repository_round_trip_and_pending_order(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'roundtrip.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    first = _outbox()
    later = OutboxEvent(
        event_type="RoleAssigned",
        occurred_at=NOW + timedelta(seconds=1),
        payload={},
    )
    published = OutboxEvent(
        event_type="AlreadyPublished",
        occurred_at=NOW + timedelta(seconds=2),
        payload={},
        status=OutboxStatus.PUBLISHED,
        published_at=NOW + timedelta(seconds=3),
    )

    with factory() as session:
        repository = SqlAlchemyOutboxRepository(session)
        repository.append(later)
        repository.append(first)
        repository.append(published)

        assert repository.get(first.id) == first
        assert repository.pending() == (first, later)
        assert repository.pending(limit=1) == (first,)

        with pytest.raises(ValueError, match="already exists"):
            repository.append(first)

        session.commit()

    engine.dispose()


def test_sqlalchemy_audit_outbox_writer_commits_business_audit_and_outbox_atomically(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'commit.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    audit = _audit()
    outbox = _outbox()

    with factory() as session:
        SqlAlchemyIdentityRepository(session).save(identity)
        SqlAlchemyAuditOutboxWriter(session).append(audit, outbox)
        session.commit()

    with factory() as session:
        assert SqlAlchemyIdentityRepository(session).exists(identity.id) is True
        assert SqlAlchemyAuditRepository(session).all() == (audit,)
        assert SqlAlchemyOutboxRepository(session).get(outbox.id) == outbox

    engine.dispose()


def test_sqlalchemy_audit_outbox_writer_rolls_back_business_audit_and_outbox_together(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'rollback.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    identity = Identity.create_user(display_name="Rollback", created_at=NOW)
    audit = _audit()
    outbox = _outbox()

    with factory() as session:
        SqlAlchemyIdentityRepository(session).save(identity)
        SqlAlchemyAuditOutboxWriter(session).append(audit, outbox)
        session.rollback()

    with factory() as session:
        assert SqlAlchemyIdentityRepository(session).exists(identity.id) is False
        assert SqlAlchemyAuditRepository(session).all() == ()
        assert SqlAlchemyOutboxRepository(session).get(outbox.id) is None

    engine.dispose()


def test_sqlalchemy_audit_outbox_writer_rolls_back_audit_when_outbox_conflicts(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'conflict.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    outbox = _outbox()

    with factory() as session:
        SqlAlchemyOutboxRepository(session).append(outbox)
        session.commit()

    audit = _audit()
    with factory() as session:
        with pytest.raises(ValueError, match="conflicts"):
            SqlAlchemyAuditOutboxWriter(session).append(audit, outbox)
        session.commit()

    with factory() as session:
        assert SqlAlchemyAuditRepository(session).all() == ()
        assert SqlAlchemyOutboxRepository(session).get(outbox.id) == outbox

    engine.dispose()



def test_sqlalchemy_outbox_repository_persists_delivery_state_transitions(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'delivery.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    event = _outbox()

    with factory() as session:
        repository = SqlAlchemyOutboxRepository(session)
        repository.append(event)

        assert repository.deliverable() == (event,)

        repository.mark_failed(event.id)
        failed = repository.get(event.id)
        assert failed is not None
        assert failed.status is OutboxStatus.FAILED
        assert failed.attempts == 1
        assert failed.published_at is None
        assert repository.pending() == ()
        assert repository.deliverable() == (failed,)

        published_at = NOW + timedelta(seconds=5)
        repository.mark_published(event.id, published_at=published_at)
        published = repository.get(event.id)
        assert published is not None
        assert published.status is OutboxStatus.PUBLISHED
        assert published.attempts == 2
        assert published.published_at == published_at
        assert repository.deliverable() == ()

        with pytest.raises(ValueError, match="not deliverable"):
            repository.mark_failed(event.id)

        session.commit()

    engine.dispose()
