from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Credential,
    CredentialStatus,
    CredentialType,
    InvalidCredential,
    InvalidCredentialTransition,
    InvalidSession,
    InvalidSessionTransition,
    Session,
    SessionStatus,
)
from pyiamkit.identity import IdentityId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def _context() -> AuthenticationContext:
    return AuthenticationContext(
        method=AuthenticationMethod.PASSWORD,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        authenticated_at=NOW,
        provider_id=" local ",
        device_id=" device-1 ",
        network_zone=" trusted ",
    )


def test_credential_lifecycle_is_temporal_and_revocable() -> None:
    identity_id = IdentityId.new()
    credential = Credential.create(
        identity_id=identity_id,
        credential_type=CredentialType.PASSKEY,
        reference=" vault://credentials/passkey-1 ",
        fingerprint=" fp-001 ",
        label=" Primary passkey ",
        created_at=NOW,
        valid_until=NOW + timedelta(days=30),
        metadata={"provider": "internal"},
    )

    assert credential.reference == "vault://credentials/passkey-1"
    assert credential.fingerprint == "fp-001"
    assert credential.label == "Primary passkey"
    assert credential.is_active(at=NOW + timedelta(days=1)) is True
    assert credential.is_active(at=NOW + timedelta(days=31)) is False
    assert credential.pull_events()[0].event_type == "CredentialCreated"

    credential.revoke(at=NOW + timedelta(days=2))
    assert credential.status is CredentialStatus.REVOKED
    assert credential.is_active(at=NOW + timedelta(days=2)) is False
    assert credential.pull_events()[0].event_type == "CredentialRevoked"
    with pytest.raises(InvalidCredentialTransition):
        credential.revoke(at=NOW + timedelta(days=3))


def test_credential_expiry_requires_valid_until() -> None:
    credential = Credential.create(
        identity_id=IdentityId.new(),
        credential_type=CredentialType.API_KEY,
        reference="vault://api-key",
        created_at=NOW,
        valid_until=NOW + timedelta(hours=1),
    )
    credential.pull_events()
    with pytest.raises(InvalidCredential):
        credential.expire(at=NOW + timedelta(minutes=30))
    credential.expire(at=NOW + timedelta(hours=1))
    assert credential.status is CredentialStatus.EXPIRED


def test_authentication_context_normalizes_optional_values() -> None:
    context = _context()
    assert context.provider_id == "local"
    assert context.device_id == "device-1"
    assert context.network_zone == "trusted"


def test_session_lifecycle_touch_revoke_and_expiry() -> None:
    session = Session.open(
        identity_id=IdentityId.new(),
        context=_context(),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=8),
    )
    assert session.is_active(at=NOW + timedelta(hours=1)) is True
    assert session.pull_events()[0].event_type == "SessionOpened"

    session.touch(at=NOW + timedelta(minutes=10))
    assert session.last_activity_at == NOW + timedelta(minutes=10)
    assert session.version == 1
    assert session.pull_events()[0].event_type == "SessionTouched"

    session.revoke(at=NOW + timedelta(minutes=20), reason=" device lost ")
    assert session.status is SessionStatus.REVOKED
    assert session.revocation_reason == "device lost"
    assert session.is_active(at=NOW + timedelta(minutes=21)) is False
    with pytest.raises(InvalidSessionTransition):
        session.touch(at=NOW + timedelta(minutes=30))


def test_session_expiry_and_time_guards() -> None:
    context = _context()
    session = Session.open(
        identity_id=IdentityId.new(),
        context=context,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    session.pull_events()
    with pytest.raises(InvalidSession):
        session.expire(at=NOW + timedelta(minutes=30))
    session.expire(at=NOW + timedelta(hours=1))
    assert session.status is SessionStatus.EXPIRED

    with pytest.raises(InvalidSession):
        Session.open(
            identity_id=IdentityId.new(),
            context=context,
            created_at=NOW,
            expires_at=NOW,
        )
