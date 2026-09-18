from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import jwt as pyjwt

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    FederatedAuthenticationService,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.authentication.adapters.oidc import (
    StaticOidcAssuranceResolver,
    StaticOidcIdTokenVerifier,
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
key = token_bytes(32)

identities = InMemoryIdentityRepository()
sessions = InMemorySessionRepository()
events = InMemoryDomainEventSink()

identity = Identity.create_user(display_name="Alice", created_at=now - timedelta(days=1))
identity.pull_events()
identity.activate(at=now - timedelta(days=1) + timedelta(minutes=1))
identity.pull_events()
identity.link_external_identity(
    provider_id="example-oidc",
    external_subject="external-subject-42",
    at=now - timedelta(hours=1),
)
identity.pull_events()
identities.save(identity)

authentication = AuthenticationApplicationService(
    identity_repository=identities,
    credential_repository=InMemoryCredentialRepository(),
    session_repository=sessions,
    clock=clock,
    event_sink=events,
)

verifier = StaticOidcIdTokenVerifier(
    provider_id="example-oidc",
    issuer="https://login.example.com",
    client_id="pyiamkit-client",
    verification_key=key,
    algorithm="HS256",
    clock=clock,
    leeway=timedelta(0),
)
assurance = StaticOidcAssuranceResolver(
    acr_mapping={"urn:example:aal2": AssuranceLevel.AAL2},
    mfa_amr_values=("mfa",),
)
federation = FederatedAuthenticationService(
    identity_repository=identities,
    authentication_service=authentication,
    token_verifier=verifier,
    assurance_resolver=assurance,
    clock=clock,
    session_ttl=timedelta(hours=8),
)

id_token = pyjwt.encode(
    {
        "iss": "https://login.example.com",
        "sub": "external-subject-42",
        "aud": "pyiamkit-client",
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "iat": int(now.timestamp()),
        "auth_time": int((now - timedelta(minutes=1)).timestamp()),
        "nonce": "nonce-123",
        "acr": "urn:example:aal2",
        "amr": ["pwd", "mfa"],
        "email": "alice@example.com",
        "email_verified": True,
    },
    key,
    algorithm="HS256",
)

session = federation.authenticate(
    id_token,
    expected_nonce="nonce-123",
    device_id="browser-1",
)

assert session.identity_id == identity.id
assert session.context.provider_id == "example-oidc"
assert session.context.assurance_level is AssuranceLevel.AAL2
assert session.context.mfa is True

print(
    "OIDC federation OK:",
    session.context.method.value,
    session.context.assurance_level.value,
)
