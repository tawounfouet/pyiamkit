from datetime import UTC, datetime, timedelta

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
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.identity import IdentityId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_inmemory_credential_repository_contract() -> None:
    repository = InMemoryCredentialRepository()
    identity_id = IdentityId.new()
    credential = Credential.create(
        identity_id=identity_id,
        credential_type=CredentialType.API_KEY,
        reference="vault://api-key/1",
        created_at=NOW,
        valid_until=NOW + timedelta(hours=1),
    )
    credential.pull_events()
    repository.save(credential)

    assert repository.get(credential.id) == credential
    assert repository.find_by_reference(" vault://api-key/1 ") == credential
    assert repository.find_for_identity(identity_id) == (credential,)
    assert repository.find_active_for_identity(identity_id, NOW) == (credential,)
    assert repository.find_active_for_identity(identity_id, NOW + timedelta(hours=2)) == ()

    credential.revoke(at=NOW + timedelta(minutes=30))
    credential.pull_events()
    repository.save(credential)
    stored = repository.get(credential.id)
    assert stored is not None
    assert stored.status is CredentialStatus.REVOKED
    assert repository.find_active_for_identity(identity_id, NOW + timedelta(minutes=31)) == ()


def test_inmemory_session_repository_contract() -> None:
    repository = InMemorySessionRepository()
    identity_id = IdentityId.new()
    session = Session.open(
        identity_id=identity_id,
        context=AuthenticationContext(
            method=AuthenticationMethod.PASSKEY,
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=2),
    )
    session.pull_events()
    repository.save(session)

    assert repository.get(session.id) == session
    assert repository.find_for_identity(identity_id) == (session,)
    assert repository.find_active_for_identity(identity_id, NOW + timedelta(hours=1)) == (session,)
    assert repository.find_active_for_identity(identity_id, NOW + timedelta(hours=3)) == ()

    session.revoke(at=NOW + timedelta(minutes=10))
    session.pull_events()
    repository.save(session)
    stored = repository.get(session.id)
    assert stored is not None
    assert stored.status is SessionStatus.REVOKED
    assert repository.find_active_for_identity(identity_id, NOW + timedelta(minutes=11)) == ()
