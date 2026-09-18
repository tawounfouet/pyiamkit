from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import jwt as pyjwt
import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    ExpiredAccessToken,
    InvalidAccessToken,
    Session,
    TokenConfigurationError,
    TokenSessionInactive,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.identity import IdentityId

NOW = datetime(2026, 9, 18, 1, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _session(
    repository: InMemorySessionRepository,
    *,
    expires_at: datetime | None = None,
) -> Session:
    session = Session.open(
        identity_id=IdentityId.new(),
        context=AuthenticationContext(
            method=AuthenticationMethod.PASSKEY,
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
            provider_id="internal",
            device_id="device-1",
            network_zone="trusted",
        ),
        created_at=NOW,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )
    session.pull_events()
    repository.save(session)
    return session


def _provider(
    repository: InMemorySessionRepository,
    clock: FrozenClock,
    *,
    key: bytes | None = None,
    issuer: str = "https://issuer.example",
    audience: str = "api://pyiamkit",
    key_id: str | None = None,
    verification_keys: dict[str, bytes] | None = None,
    ttl: timedelta = timedelta(minutes=15),
    leeway: timedelta = timedelta(0),
) -> JwtTokenProvider:
    signing_key = key or token_bytes(32)
    return JwtTokenProvider(
        issuer=issuer,
        audience=audience,
        signing_key=signing_key,
        session_repository=repository,
        clock=clock,
        algorithm="HS256",
        access_token_ttl=ttl,
        leeway=leeway,
        key_id=key_id,
        verification_keys=verification_keys,
    )


def test_issue_and_verify_access_token_keeps_session_authoritative() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    key = token_bytes(32)
    session = _session(repository)
    provider = _provider(repository, clock, key=key)

    issued = provider.issue_access_token(session)
    verified = provider.verify_access_token(issued.token)
    raw_payload = pyjwt.decode(issued.token, options={"verify_signature": False})

    assert verified == issued.claims
    assert verified.subject_id == session.identity_id
    assert verified.session_id == session.id
    assert verified.assurance_level is AssuranceLevel.AAL2
    assert verified.authentication_method is AuthenticationMethod.PASSKEY
    assert verified.mfa is True
    assert "roles" not in raw_payload
    assert "permissions" not in raw_payload
    assert raw_payload["token_use"] == "access"


def test_access_token_expiration_is_capped_by_session_expiration() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    session = _session(repository, expires_at=NOW + timedelta(minutes=5))
    provider = _provider(repository, clock, ttl=timedelta(minutes=30))

    issued = provider.issue_access_token(session)

    assert issued.claims.expires_at == session.expires_at


def test_expired_access_token_is_rejected_using_injected_clock() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    session = _session(repository)
    provider = _provider(repository, clock, ttl=timedelta(minutes=5))

    issued = provider.issue_access_token(session)
    clock.value = NOW + timedelta(minutes=5)

    with pytest.raises(ExpiredAccessToken):
        provider.verify_access_token(issued.token)


def test_revoked_session_invalidates_previously_issued_token() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    session = _session(repository)
    provider = _provider(repository, clock)

    issued = provider.issue_access_token(session)
    clock.value = NOW + timedelta(minutes=1)
    session.revoke(at=clock.now(), reason="logout")
    session.pull_events()
    repository.save(session)

    with pytest.raises(TokenSessionInactive):
        provider.verify_access_token(issued.token)


@pytest.mark.parametrize(
    ("issuer", "audience"),
    [
        ("https://other-issuer.example", "api://pyiamkit"),
        ("https://issuer.example", "api://other"),
    ],
)
def test_wrong_issuer_or_audience_is_rejected(issuer: str, audience: str) -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    key = token_bytes(32)
    session = _session(repository)
    issuer_provider = _provider(repository, clock, key=key)
    verifier = _provider(
        repository,
        clock,
        key=key,
        issuer=issuer,
        audience=audience,
    )

    issued = issuer_provider.issue_access_token(session)

    with pytest.raises(InvalidAccessToken):
        verifier.verify_access_token(issued.token)


def test_tampered_token_is_rejected() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    session = _session(repository)
    provider = _provider(repository, clock)

    issued = provider.issue_access_token(session)
    prefix, payload, signature = issued.token.split(".")
    replacement = "A" if payload[0] != "A" else "B"
    tampered = ".".join((prefix, replacement + payload[1:], signature))

    with pytest.raises(InvalidAccessToken):
        provider.verify_access_token(tampered)


def test_configured_algorithm_cannot_be_selected_from_token_header() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    key = token_bytes(48)
    provider = _provider(repository, clock, key=key)
    attacker_token = pyjwt.encode(
        {"sub": "not-relevant"},
        key,
        algorithm="HS384",
        headers={"typ": "JWT"},
    )

    with pytest.raises(InvalidAccessToken, match="algorithm"):
        provider.verify_access_token(attacker_token)


def test_unknown_or_missing_kid_is_rejected_when_key_set_is_configured() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    key = token_bytes(32)
    session = _session(repository)
    provider = _provider(
        repository,
        clock,
        key=key,
        key_id="current",
        verification_keys={"current": key},
    )
    issued = provider.issue_access_token(session)
    payload = pyjwt.decode(issued.token, options={"verify_signature": False})

    unknown = pyjwt.encode(
        payload,
        key,
        algorithm="HS256",
        headers={"typ": "JWT", "kid": "unknown"},
    )
    missing = pyjwt.encode(
        payload,
        key,
        algorithm="HS256",
        headers={"typ": "JWT"},
    )

    with pytest.raises(InvalidAccessToken, match="unknown"):
        provider.verify_access_token(unknown)
    with pytest.raises(InvalidAccessToken, match="required"):
        provider.verify_access_token(missing)


def test_unsafe_or_incomplete_configuration_is_rejected() -> None:
    repository = InMemorySessionRepository()
    clock = FrozenClock(NOW)
    key = token_bytes(32)

    with pytest.raises(TokenConfigurationError, match="Unsupported or unsafe"):
        JwtTokenProvider(
            issuer="https://issuer.example",
            audience="api://pyiamkit",
            signing_key=key,
            session_repository=repository,
            clock=clock,
            algorithm="none",
        )

    with pytest.raises(TokenConfigurationError, match="key_id"):
        JwtTokenProvider(
            issuer="https://issuer.example",
            audience="api://pyiamkit",
            signing_key=key,
            session_repository=repository,
            clock=clock,
            algorithm="HS256",
            verification_keys={"old": token_bytes(32)},
        )
