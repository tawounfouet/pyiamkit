from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import pyotp

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    MfaApplicationService,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemoryMfaFactorRepository,
    InMemorySessionRepository,
)
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.authentication.adapters.totp import (
    InMemoryMfaSecretStore,
    PyOtpTotpProvider,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = MutableClock(now)

identities = InMemoryIdentityRepository()
credentials = InMemoryCredentialRepository()
sessions = InMemorySessionRepository()
factors = InMemoryMfaFactorRepository()
events = InMemoryDomainEventSink()
secret_store = InMemoryMfaSecretStore()

identity = Identity.create_user(display_name="Alice", created_at=now - timedelta(days=1))
identity.pull_events()
identity.activate(at=now - timedelta(days=1) + timedelta(minutes=1))
identity.pull_events()
identities.save(identity)

authentication = AuthenticationApplicationService(
    identity_repository=identities,
    credential_repository=credentials,
    session_repository=sessions,
    clock=clock,
    event_sink=events,
)

totp_provider = PyOtpTotpProvider(
    secret_store=secret_store,
    issuer_name="PyIAMKit Example",
    valid_window=0,
)

mfa = MfaApplicationService(
    identity_repository=identities,
    factor_repository=factors,
    session_repository=sessions,
    totp_provider=totp_provider,
    clock=clock,
    event_sink=events,
)

enrollment = mfa.begin_totp_enrollment(
    identity_id=identity.id,
    account_name="alice@example.com",
    label="Alice authenticator",
)

secret = secret_store.get(enrollment.factor.secret_reference)
assert secret is not None

first_code = pyotp.TOTP(secret).at(clock.now())
factor = mfa.confirm_totp_enrollment(
    enrollment.factor.id,
    code=first_code,
)

session = authentication.open_session(
    identity_id=identity.id,
    method=AuthenticationMethod.PASSWORD,
    assurance_level=AssuranceLevel.AAL1,
    mfa=False,
    expires_at=now + timedelta(hours=1),
)

tokens = JwtTokenProvider(
    issuer="https://iam.example.com",
    audience="api://example",
    signing_key=token_bytes(32),
    session_repository=sessions,
    clock=clock,
    algorithm="HS256",
    leeway=timedelta(0),
)

old_token = tokens.issue_access_token(session).token

clock.value = now + timedelta(seconds=30)
step_up_code = pyotp.TOTP(secret).at(clock.now())

elevated = mfa.step_up_totp_session(
    session.id,
    factor_id=factor.id,
    code=step_up_code,
)

assert elevated.context.assurance_level is AssuranceLevel.AAL2
assert elevated.context.mfa is True

new_token = tokens.issue_access_token(elevated).token
claims = tokens.verify_access_token(new_token)

assert claims.assurance_level is AssuranceLevel.AAL2
assert claims.mfa is True

print(
    "MFA step-up OK:",
    elevated.context.assurance_level.value,
    elevated.context.mfa,
)
