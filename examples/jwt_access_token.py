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


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)
sessions = InMemorySessionRepository()

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
)

issued = tokens.issue_access_token(session)
claims = tokens.verify_access_token(issued.token)

assert claims.session_id == session.id
assert claims.subject_id == session.identity_id
assert claims.assurance_level is AssuranceLevel.AAL2

print(
    "Access token verified:",
    claims.authentication_method.value,
    claims.assurance_level.value,
)

clock.value = now + timedelta(minutes=1)
session.revoke(at=clock.now(), reason="logout")
session.pull_events()
sessions.save(session)

try:
    tokens.verify_access_token(issued.token)
except TokenSessionInactive:
    print("Previously issued token rejected after Session revocation")
else:
    raise RuntimeError("Revoked Session unexpectedly accepted an access token")
