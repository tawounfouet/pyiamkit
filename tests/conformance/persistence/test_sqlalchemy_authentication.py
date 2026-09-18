from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session as SqlAlchemySession

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Credential,
    CredentialStatus,
    CredentialType,
    Session,
    SessionStatus,
)
from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyCredentialRepository,
    SqlAlchemyIdentityRepository,
    SqlAlchemySessionRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def db_session(tmp_path: Path) -> Iterator[SqlAlchemySession]:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'authentication.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        yield session
    engine.dispose()


def _active_identity(session: SqlAlchemySession) -> Identity:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    SqlAlchemyIdentityRepository(session).save(identity)
    return identity


@pytest.mark.conformance
def test_sqlalchemy_credential_round_trip_and_temporal_filter(\n    db_session: SqlAlchemySession,\n) -> None:
    identity = _active_identity(db_session)
    repository = SqlAlchemyCredentialRepository(db_session)
    credential = Credential.create(
        identity_id=identity.id,
        credential_type=CredentialType.PASSKEY,
        reference="vault://credentials/passkey-1",
        fingerprint="sha256:abc",
        label="Primary passkey",
        created_at=NOW,
        valid_until=NOW + timedelta(days=30),
        metadata={"provider": "internal"},
    )
    credential.pull_events()
    repository.save(credential)

    loaded = repository.get(credential.id)
    assert loaded == credential
    assert loaded is not None
    assert loaded.reference == "vault://credentials/passkey-1"
    assert loaded.metadata["provider"] == "internal"
    assert repository.find_by_reference(" vault://credentials/passkey-1 ") == credential
    assert repository.find_for_identity(identity.id) == (credential,)
    assert repository.find_active_for_identity(
        identity.id,
        NOW + timedelta(days=1),
    ) == (credential,)
    assert repository.find_active_for_identity(identity.id, NOW + timedelta(days=31)) == ()

    credential.revoke(at=NOW + timedelta(days=2))
    credential.pull_events()
    repository.save(credential)
    revoked = repository.get(credential.id)
    assert revoked is not None
    assert revoked.status is CredentialStatus.REVOKED


@pytest.mark.conformance
def test_sqlalchemy_session_round_trip_and_expiry_filter(db_session: SqlAlchemySession) -> None:
    identity = _active_identity(db_session)
    repository = SqlAlchemySessionRepository(db_session)
    session = Session.open(
        identity_id=identity.id,
        context=AuthenticationContext(
            method=AuthenticationMethod.OIDC,
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
            provider_id="entra",
            device_id="device-1",
            network_zone="trusted",
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=8),
    )
    session.pull_events()
    repository.save(session)

    loaded = repository.get(session.id)
    assert loaded == session
    assert loaded is not None
    assert loaded.context.provider_id == "entra"
    assert loaded.context.assurance_level is AssuranceLevel.AAL2
    assert loaded.context.mfa is True
    assert repository.find_for_identity(identity.id) == (session,)
    assert repository.find_active_for_identity(
        identity.id,
        NOW + timedelta(hours=1),
    ) == (session,)
    assert repository.find_active_for_identity(identity.id, NOW + timedelta(hours=9)) == ()

    session.revoke(at=NOW + timedelta(hours=1), reason="security reset")
    session.pull_events()
    repository.save(session)
    revoked = repository.get(session.id)
    assert revoked is not None
    assert revoked.status is SessionStatus.REVOKED
    assert revoked.revocation_reason == "security reset"
    assert repository.find_active_for_identity(identity.id, NOW + timedelta(hours=2)) == ()
