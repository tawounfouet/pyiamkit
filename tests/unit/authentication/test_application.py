from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    AuthenticationSubjectInactive,
    CredentialAlreadyExists,
    CredentialStatus,
    CredentialType,
    SessionStatus,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _setup(*, active: bool = True):
    identities = InMemoryIdentityRepository()
    credentials = InMemoryCredentialRepository()
    sessions = InMemorySessionRepository()
    events = InMemoryDomainEventSink()
    clock = FrozenClock(NOW)

    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()
    if active:
        identity.activate(at=NOW)
        identity.pull_events()
    identities.save(identity)

    service = AuthenticationApplicationService(
        identity_repository=identities,
        credential_repository=credentials,
        session_repository=sessions,
        clock=clock,
        event_sink=events,
    )
    return service, identity, credentials, sessions, events, clock


def test_register_and_revoke_credential() -> None:
    service, identity, credentials, _, events, clock = _setup()
    credential = service.register_credential(
        identity_id=identity.id,
        credential_type=CredentialType.PASSKEY,
        reference="vault://passkey/1",
        fingerprint="fp1",
        valid_until=NOW + timedelta(days=90),
    )
    assert credentials.get(credential.id) is not None
    assert events.events[-1].event_type == "CredentialCreated"

    clock.value = NOW + timedelta(minutes=1)
    revoked = service.revoke_credential(credential.id)
    assert revoked.status is CredentialStatus.REVOKED
    assert service.active_credentials(identity.id) == ()


def test_duplicate_credential_reference_is_rejected() -> None:
    service, identity, *_ = _setup()
    kwargs = {
        "identity_id": identity.id,
        "credential_type": CredentialType.API_KEY,
        "reference": "vault://api-key/1",
    }
    service.register_credential(**kwargs)
    with pytest.raises(CredentialAlreadyExists):
        service.register_credential(**kwargs)


def test_inactive_identity_cannot_register_or_open_session() -> None:
    service, identity, *_ = _setup(active=False)
    with pytest.raises(AuthenticationSubjectInactive):
        service.register_credential(
            identity_id=identity.id,
            credential_type=CredentialType.PASSWORD,
            reference="vault://password/1",
        )
    with pytest.raises(AuthenticationSubjectInactive):
        service.open_session(
            identity_id=identity.id,
            method=AuthenticationMethod.PASSWORD,
            assurance_level=AssuranceLevel.AAL1,
            mfa=False,
            expires_at=NOW + timedelta(hours=1),
        )


def test_session_open_touch_revoke_and_bulk_revocation() -> None:
    service, identity, _, sessions, events, clock = _setup()
    first = service.open_session(
        identity_id=identity.id,
        method=AuthenticationMethod.OIDC,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        expires_at=NOW + timedelta(hours=8),
        provider_id="entra",
    )
    second = service.open_session(
        identity_id=identity.id,
        method=AuthenticationMethod.PASSKEY,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        expires_at=NOW + timedelta(hours=4),
    )
    assert len(service.active_sessions(identity.id)) == 2

    clock.value = NOW + timedelta(minutes=5)
    touched = service.touch_session(first.id)
    assert touched.last_activity_at == clock.value

    clock.value = NOW + timedelta(minutes=10)
    revoked = service.revoke_session(first.id, reason="device lost")
    assert revoked.status is SessionStatus.REVOKED
    assert sessions.get(first.id).revocation_reason == "device lost"  # type: ignore[union-attr]

    clock.value = NOW + timedelta(minutes=15)
    bulk = service.revoke_all_sessions(identity.id, reason="account security")
    assert tuple(item.id for item in bulk) == (second.id,)
    assert service.active_sessions(identity.id) == ()
    assert "SessionRevoked" in [event.event_type for event in events.events]
