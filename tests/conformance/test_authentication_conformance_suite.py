from datetime import UTC, datetime, timedelta
from itertools import count
from secrets import token_bytes

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    Session,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.authentication.adapters.totp import InMemoryMfaSecretStore
from pyiamkit.conformance import (
    AuthenticationConformance,
    AuthenticationProbe,
    SecretStoreConformance,
    SecretStoreProbe,
    TokenProviderConformance,
    TokenProviderProbe,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryDomainEventSink, InMemoryIdentityRepository
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 3, 9, 30, tzinfo=UTC)

pytestmark = pytest.mark.conformance


class MutableClock(Clock):
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _authentication_stack(
    *,
    active: bool = True,
) -> tuple[
    AuthenticationApplicationService,
    Identity,
    InMemorySessionRepository,
    MutableClock,
]:
    identities = InMemoryIdentityRepository()
    credentials = InMemoryCredentialRepository()
    sessions = InMemorySessionRepository()
    events = InMemoryDomainEventSink()
    clock = MutableClock()

    identity = Identity.create_user(display_name="Conformance User", created_at=NOW)
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
    return service, identity, sessions, clock


def _open_session(
    service: AuthenticationApplicationService,
    identity: Identity,
    *,
    expires_at: datetime,
) -> Session:
    return service.open_session(
        identity_id=identity.id,
        method=AuthenticationMethod.PASSKEY,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        expires_at=expires_at,
    )


def _active_session() -> Session:
    service, identity, _, _ = _authentication_stack()
    return _open_session(service, identity, expires_at=NOW + timedelta(hours=1))


def _inactive_session_attempt() -> None:
    service, identity, _, _ = _authentication_stack(active=False)
    _open_session(service, identity, expires_at=NOW + timedelta(hours=1))


def _revoked_session() -> Session:
    service, identity, _, clock = _authentication_stack()
    session = _open_session(service, identity, expires_at=NOW + timedelta(hours=1))
    clock.value = NOW + timedelta(minutes=1)
    return service.revoke_session(session.id, reason="conformance")


def _expired_session() -> Session:
    service, identity, _, clock = _authentication_stack()
    session = _open_session(service, identity, expires_at=NOW + timedelta(minutes=5))
    clock.value = session.expires_at
    return service.expire_session(session.id)


def _revoke_all_sessions() -> tuple[tuple[Session, ...], tuple[Session, ...]]:
    service, identity, _, clock = _authentication_stack()
    _open_session(service, identity, expires_at=NOW + timedelta(hours=1))
    _open_session(service, identity, expires_at=NOW + timedelta(hours=2))
    clock.value = NOW + timedelta(minutes=1)
    revoked = service.revoke_all_sessions(identity.id, reason="conformance")
    return revoked, service.active_sessions(identity.id)


def test_authentication_conformance_qualifies_application_service() -> None:
    report = AuthenticationConformance(
        AuthenticationProbe(
            name="AuthenticationApplicationService[InMemory]",
            open_active_session=_active_session,
            open_for_inactive_subject=_inactive_session_attempt,
            revoke_session=_revoked_session,
            expire_session=_expired_session,
            revoke_all_sessions=_revoke_all_sessions,
        )
    ).run()

    report.require_passed()
    assert report.passed is True


def _token_session(
    repository: InMemorySessionRepository,
    *,
    expires_at: datetime | None = None,
) -> Session:
    session = Session.open(
        identity_id=Identity.create_user(
            display_name="Token Subject",
            created_at=NOW,
        ).id,
        context=_active_session().context,
        created_at=NOW,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )
    session.pull_events()
    repository.save(session)
    return session


def _token_provider(
    repository: InMemorySessionRepository,
    clock: MutableClock,
    *,
    key: bytes,
    issuer: str = "https://issuer.example",
    audience: str = "api://pyiamkit",
    ttl: timedelta = timedelta(minutes=15),
) -> JwtTokenProvider:
    return JwtTokenProvider(
        issuer=issuer,
        audience=audience,
        signing_key=key,
        session_repository=repository,
        clock=clock,
        algorithm="HS256",
        access_token_ttl=ttl,
        leeway=timedelta(0),
    )


def _token_round_trip():
    repository = InMemorySessionRepository()
    clock = MutableClock()
    key = token_bytes(32)
    session = _token_session(repository)
    provider = _token_provider(repository, clock, key=key)
    issued = provider.issue_access_token(session)
    return issued, provider.verify_access_token(issued.token)


def _tampered_token() -> None:
    repository = InMemorySessionRepository()
    clock = MutableClock()
    key = token_bytes(32)
    session = _token_session(repository)
    provider = _token_provider(repository, clock, key=key)
    token = provider.issue_access_token(session).token
    header, payload, signature = token.split(".")
    replacement = "A" if payload[0] != "A" else "B"
    provider.verify_access_token(".".join((header, replacement + payload[1:], signature)))


def _expired_token() -> None:
    repository = InMemorySessionRepository()
    clock = MutableClock()
    key = token_bytes(32)
    session = _token_session(repository)
    provider = _token_provider(
        repository,
        clock,
        key=key,
        ttl=timedelta(minutes=5),
    )
    token = provider.issue_access_token(session).token
    clock.value = NOW + timedelta(minutes=5)
    provider.verify_access_token(token)


def _wrong_trust_context() -> None:
    repository = InMemorySessionRepository()
    clock = MutableClock()
    key = token_bytes(32)
    session = _token_session(repository)
    issuer = _token_provider(repository, clock, key=key)
    verifier = _token_provider(
        repository,
        clock,
        key=key,
        audience="api://other",
    )
    verifier.verify_access_token(issuer.issue_access_token(session).token)


def _revoked_session_token() -> None:
    repository = InMemorySessionRepository()
    clock = MutableClock()
    key = token_bytes(32)
    session = _token_session(repository)
    provider = _token_provider(repository, clock, key=key)
    token = provider.issue_access_token(session).token
    clock.value = NOW + timedelta(minutes=1)
    session.revoke(at=clock.now(), reason="conformance")
    session.pull_events()
    repository.save(session)
    provider.verify_access_token(token)


def test_token_provider_conformance_qualifies_jwt_adapter() -> None:
    report = TokenProviderConformance(
        TokenProviderProbe(
            name="JwtTokenProvider[HS256]",
            valid_round_trip=_token_round_trip,
            tampered_token=_tampered_token,
            expired_token=_expired_token,
            wrong_trust_context=_wrong_trust_context,
            revoked_session_token=_revoked_session_token,
        )
    ).run()

    report.require_passed()
    assert report.passed is True


def test_secret_store_conformance_qualifies_inmemory_mfa_store() -> None:
    store = InMemoryMfaSecretStore()
    sequence = count(1)
    report = SecretStoreConformance(
        SecretStoreProbe(
            name="InMemoryMfaSecretStore",
            put=store.put,
            get=store.get,
            delete=store.delete,
            reference=lambda: f"mfa://conformance/{next(sequence)}",
            secret=lambda: "JBSWY3DPEHPK3PXP",
        )
    ).run()

    report.require_passed()
    assert report.passed is True
