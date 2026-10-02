"""JWT deny-fast revocation overlay backed by the shared operational registry."""

from datetime import UTC, datetime, timedelta
from secrets import token_bytes

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Session,
    TokenSessionInactive,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.identity import IdentityId
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink
from pyiamkit.operations import SecurityStateMutationEventSink
from pyiamkit.operations.adapters import (
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 10, 2, 8, 30, tzinfo=UTC)
clock = MutableClock(now)
sessions = InMemorySessionRepository()
revocations = InMemoryRevocationRegistry()
state = InMemorySecurityStateStore()
events = SecurityStateMutationEventSink(
    InMemoryDomainEventSink(),
    state_writer=state,
    revocations=revocations,
)

session = Session.open(
    identity_id=IdentityId.new(),
    context=AuthenticationContext(
        method=AuthenticationMethod.PASSKEY,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        authenticated_at=now,
    ),
    created_at=now,
    expires_at=now + timedelta(hours=8),
)
session.pull_events()
sessions.save(session)

tokens = JwtTokenProvider(
    issuer="https://iam.example.com",
    audience="api://billing",
    signing_key=token_bytes(32),
    session_repository=sessions,
    clock=clock,
    algorithm="HS256",
    revocation_registry=revocations,
)

issued = tokens.issue_access_token(session)
assert tokens.verify_access_token(issued.token).session_id == session.id

clock.value = now + timedelta(minutes=1)
session.revoke(at=clock.now(), reason="logout")
events.publish(session.pull_events())
sessions.save(session)

try:
    tokens.verify_access_token(issued.token)
except TokenSessionInactive:
    print("Revoked Session rejected by the JWT revocation overlay")
else:
    raise RuntimeError("Revoked Session unexpectedly accepted an access token")
