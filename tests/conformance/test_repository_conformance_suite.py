from datetime import UTC, datetime
from pathlib import Path

import pytest

from pyiamkit.conformance import (
    ConformanceFailure,
    RepositoryConformance,
    RepositoryProbe,
)
from pyiamkit.identity import Identity, IdentityId
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyIdentityRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=UTC)

pytestmark = pytest.mark.conformance


def _identity() -> Identity:
    return Identity.create_user(display_name="Conformance User", created_at=NOW)


def _snapshot(identity: Identity) -> object:
    return (
        identity.id,
        identity.version,
        identity.type,
        identity.status,
        identity.display_name,
        identity.profile,
        identity.created_at,
        identity.updated_at,
        identity.activated_at,
        identity.suspended_at,
        identity.disabled_at,
        identity.archived_at,
        identity.external_links,
        dict(identity.metadata),
    )


def _mutate(identity: Identity) -> None:
    identity.activate(at=NOW)


def _assert_rehydrated_without_events(identity: Identity) -> None:
    if identity.pull_events() != ():
        raise AssertionError("rehydrated Identity emitted pending domain events")


def _identity_probe(
    *,
    name: str,
    save,
    get,
    exists,
) -> RepositoryProbe[Identity, IdentityId]:
    return RepositoryProbe(
        name=name,
        create=_identity,
        identifier=lambda identity: identity.id,
        missing_identifier=IdentityId.new,
        save=save,
        get=get,
        snapshot=_snapshot,
        mutate=_mutate,
        exists=exists,
        after_load=_assert_rehydrated_without_events,
    )


def test_repository_conformance_qualifies_inmemory_identity_repository() -> None:
    repository = InMemoryIdentityRepository()
    suite = RepositoryConformance(
        _identity_probe(
            name="InMemoryIdentityRepository",
            save=repository.save,
            get=repository.get,
            exists=repository.exists,
        )
    )

    report = suite.run()

    report.require_passed()
    assert report.passed is True
    assert report.failures == ()
    assert {check.name for check in report.checks} == {
        "missing_read_returns_none",
        "round_trip_preserves_state",
        "round_trip_returns_copy",
        "exists_tracks_persistence",
        "save_is_snapshot_isolated",
        "loaded_value_is_snapshot_isolated",
        "rehydration_invariant",
    }


def test_repository_conformance_qualifies_sqlalchemy_identity_repository(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'conformance.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)

    with factory() as session:
        repository = SqlAlchemyIdentityRepository(session)
        report = RepositoryConformance(
            _identity_probe(
                name="SqlAlchemyIdentityRepository[SQLite]",
                save=repository.save,
                get=repository.get,
                exists=repository.exists,
            )
        ).run()

        report.require_passed()
        session.rollback()

    engine.dispose()


class AliasingIdentityRepository:
    def __init__(self) -> None:
        self._items: dict[IdentityId, Identity] = {}

    def save(self, identity: Identity) -> None:
        self._items[identity.id] = identity

    def get(self, identity_id: IdentityId) -> Identity | None:
        return self._items.get(identity_id)

    def exists(self, identity_id: IdentityId) -> bool:
        return identity_id in self._items


def test_repository_conformance_rejects_aliasing_repository() -> None:
    repository = AliasingIdentityRepository()
    report = RepositoryConformance(
        _identity_probe(
            name="AliasingIdentityRepository",
            save=repository.save,
            get=repository.get,
            exists=repository.exists,
        )
    ).run()

    assert report.passed is False
    assert {check.name for check in report.failures} >= {
        "round_trip_returns_copy",
        "save_is_snapshot_isolated",
        "loaded_value_is_snapshot_isolated",
    }
    with pytest.raises(ConformanceFailure, match="AliasingIdentityRepository"):
        report.require_passed()
