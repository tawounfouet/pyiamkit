from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import pyotp
import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    InvalidAccessToken,
    MfaApplicationService,
    MfaFactorOwnershipMismatch,
    MfaVerificationFailed,
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

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _active_identity(repository: InMemoryIdentityRepository, *, name: str = "Alice") -> Identity:
    identity = Identity.create_user(display_name=name, created_at=NOW - timedelta(days=1))
    identity.pull_events()
    identity.activate(at=NOW - timedelta(days=1) + timedelta(minutes=1))
    identity.pull_events()
    repository.save(identity)
    return identity


def _stack():
    clock = FrozenClock(NOW)
    identities = InMemoryIdentityRepository()
    factors = InMemoryMfaFactorRepository()
    sessions = InMemorySessionRepository()
    events = InMemoryDomainEventSink()
    secrets = InMemoryMfaSecretStore()
    totp = PyOtpTotpProvider(
        secret_store=secrets,
        issuer_name="PyIAMKit",
        valid_window=0,
    )
    authentication = AuthenticationApplicationService(
        identity_repository=identities,
        credential_repository=InMemoryCredentialRepository(),
        session_repository=sessions,
        clock=clock,
        event_sink=events,
    )
    mfa = MfaApplicationService(
        identity_repository=identities,
        factor_repository=factors,
        session_repository=sessions,
        totp_provider=totp,
        clock=clock,
        event_sink=events,
    )
    return clock, identities, factors, sessions, secrets, authentication, mfa


def _code(secrets: InMemoryMfaSecretStore, reference: str, at: datetime) -> str:
    secret = secrets.get(reference)
    assert secret is not None
    return pyotp.TOTP(secret).at(at)


def test_totp_enrollment_requires_first_valid_code_and_rejects_replay() -> None:
    clock, identities, _, _, secrets, _, mfa = _stack()
    identity = _active_identity(identities)

    enrollment = mfa.begin_totp_enrollment(
        identity_id=identity.id,
        account_name="alice@example.com",
        label="Authenticator",
    )
    factor = enrollment.factor

    assert factor.status.value == "pending"
    assert factor.secret_reference.startswith("mfa://totp/")
    assert "secret=" in enrollment.provisioning_uri

    with pytest.raises(MfaVerificationFailed):
        mfa.confirm_totp_enrollment(factor.id, code="000000")

    first_code = _code(secrets, factor.secret_reference, clock.now())
    active = mfa.confirm_totp_enrollment(factor.id, code=first_code)
    assert active.status.value == "active"
    assert active.last_accepted_counter is not None

    with pytest.raises(MfaVerificationFailed):
        mfa.verify_totp(factor.id, code=first_code)

    clock.value = NOW + timedelta(seconds=30)
    second_code = _code(secrets, factor.secret_reference, clock.now())
    verified = mfa.verify_totp(factor.id, code=second_code)
    assert verified.last_accepted_counter is not None
    assert verified.last_accepted_counter > active.last_accepted_counter


def test_totp_step_up_updates_session_and_invalidates_old_access_token() -> None:
    clock, identities, _, sessions, secrets, authentication, mfa = _stack()
    identity = _active_identity(identities)

    enrollment = mfa.begin_totp_enrollment(
        identity_id=identity.id,
        account_name="alice@example.com",
    )
    first_code = _code(secrets, enrollment.factor.secret_reference, clock.now())
    mfa.confirm_totp_enrollment(enrollment.factor.id, code=first_code)

    session = authentication.open_session(
        identity_id=identity.id,
        method=AuthenticationMethod.PASSWORD,
        assurance_level=AssuranceLevel.AAL1,
        mfa=False,
        expires_at=NOW + timedelta(hours=1),
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
    assert tokens.verify_access_token(old_token).assurance_level is AssuranceLevel.AAL1

    clock.value = NOW + timedelta(seconds=30)
    step_up_code = _code(secrets, enrollment.factor.secret_reference, clock.now())
    elevated = mfa.step_up_totp_session(
        session.id,
        factor_id=enrollment.factor.id,
        code=step_up_code,
    )

    assert elevated.context.assurance_level is AssuranceLevel.AAL2
    assert elevated.context.mfa is True
    assert elevated.context.mfa_verified_at == clock.now()
    assert elevated.context.mfa_factor_id == str(enrollment.factor.id)

    with pytest.raises(InvalidAccessToken):
        tokens.verify_access_token(old_token)

    new_token = tokens.issue_access_token(elevated).token
    claims = tokens.verify_access_token(new_token)
    assert claims.assurance_level is AssuranceLevel.AAL2
    assert claims.mfa is True


def test_factor_cannot_step_up_another_identity_session() -> None:
    clock, identities, _, _, secrets, authentication, mfa = _stack()
    alice = _active_identity(identities, name="Alice")
    bob = _active_identity(identities, name="Bob")

    enrollment = mfa.begin_totp_enrollment(
        identity_id=alice.id,
        account_name="alice@example.com",
    )
    mfa.confirm_totp_enrollment(
        enrollment.factor.id,
        code=_code(secrets, enrollment.factor.secret_reference, clock.now()),
    )
    bob_session = authentication.open_session(
        identity_id=bob.id,
        method=AuthenticationMethod.PASSWORD,
        assurance_level=AssuranceLevel.AAL1,
        mfa=False,
        expires_at=NOW + timedelta(hours=1),
    )

    clock.value = NOW + timedelta(seconds=30)
    with pytest.raises(MfaFactorOwnershipMismatch):
        mfa.step_up_totp_session(
            bob_session.id,
            factor_id=enrollment.factor.id,
            code=_code(secrets, enrollment.factor.secret_reference, clock.now()),
        )


def test_revoke_factor_fails_closed_and_removes_secret_material() -> None:
    clock, identities, _, _, secrets, _, mfa = _stack()
    identity = _active_identity(identities)
    enrollment = mfa.begin_totp_enrollment(
        identity_id=identity.id,
        account_name="alice@example.com",
    )
    mfa.confirm_totp_enrollment(
        enrollment.factor.id,
        code=_code(secrets, enrollment.factor.secret_reference, clock.now()),
    )

    revoked = mfa.revoke_factor(enrollment.factor.id)

    assert revoked.status.value == "revoked"
    assert secrets.get(revoked.secret_reference) is None
    assert mfa.active_factors_for_identity(identity.id) == ()
