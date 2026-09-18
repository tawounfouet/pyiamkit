from datetime import UTC, datetime, timedelta

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    CredentialType,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)
identities = InMemoryIdentityRepository()
credentials = InMemoryCredentialRepository()
sessions = InMemorySessionRepository()
events = InMemoryDomainEventSink()

identity = Identity.create_user(display_name="Alice", created_at=now)
identity.pull_events()
identity.activate(at=now)
identity.pull_events()
identities.save(identity)

authentication = AuthenticationApplicationService(
    identity_repository=identities,
    credential_repository=credentials,
    session_repository=sessions,
    clock=clock,
    event_sink=events,
)

credential = authentication.register_credential(
    identity_id=identity.id,
    credential_type=CredentialType.PASSKEY,
    reference="vault://iam/passkeys/alice/device-1",
    fingerprint="sha256:public-example-fingerprint",
    label="Alice laptop passkey",
)

session = authentication.open_session(
    identity_id=identity.id,
    method=AuthenticationMethod.PASSKEY,
    assurance_level=AssuranceLevel.AAL2,
    mfa=True,
    expires_at=now + timedelta(hours=8),
    device_id="device-1",
    network_zone="trusted",
)

assert credential.reference.startswith("vault://")
assert session.context.assurance_level is AssuranceLevel.AAL2
assert authentication.active_credentials(identity.id) == (credential,)
assert authentication.active_sessions(identity.id) == (session,)

clock.value = now + timedelta(minutes=10)
revoked = authentication.revoke_all_sessions(identity.id, reason="user logout")

assert revoked == (session,)
assert authentication.active_sessions(identity.id) == ()

print(
    "Authentication lifecycle OK:",
    credential.type.value,
    session.context.method.value,
    session.context.assurance_level.value,
)
