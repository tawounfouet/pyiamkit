from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationApplicationService,
    AuthenticationMethod,
    AuthenticationSubjectInactive,
    ExternalIdentityNotLinked,
    FederatedAssurance,
    FederatedAuthenticationService,
    FederatedIdentityClaims,
    InvalidFederationPolicy,
)
from pyiamkit.authentication.adapters import (
    InMemoryCredentialRepository,
    InMemorySessionRepository,
)
from pyiamkit.identity import EmailAddress, Identity
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


class StubVerifier:
    def __init__(self, claims: FederatedIdentityClaims) -> None:
        self.claims = claims
        self.expected_nonce: str | None = None

    def verify_identity_token(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> FederatedIdentityClaims:
        assert token == "verified-id-token"
        self.expected_nonce = expected_nonce
        return self.claims


class StubAssuranceResolver:
    def resolve(self, claims: FederatedIdentityClaims) -> FederatedAssurance:
        assert claims.provider_id == "entra-prod"
        return FederatedAssurance(level=AssuranceLevel.AAL2, mfa=True)


def _claims(
    *,
    subject: str = "external-user-42",
    email: str | None = "alice@example.com",
) -> FederatedIdentityClaims:
    return FederatedIdentityClaims(
        provider_id="entra-prod",
        issuer="https://login.example.com/tenant/v2.0",
        subject=subject,
        audiences=("pyiamkit-client",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        auth_time=NOW - timedelta(minutes=1),
        nonce="nonce-123",
        acr="urn:example:aal2",
        amr=("pwd", "mfa"),
        email=email,
        email_verified=True if email is not None else None,
    )


def _services(
    claims: FederatedIdentityClaims,
) -> tuple[
    FederatedAuthenticationService,
    InMemoryIdentityRepository,
    InMemorySessionRepository,
    StubVerifier,
]:
    clock = FrozenClock(NOW)
    identities = InMemoryIdentityRepository()
    sessions = InMemorySessionRepository()
    authentication = AuthenticationApplicationService(
        identity_repository=identities,
        credential_repository=InMemoryCredentialRepository(),
        session_repository=sessions,
        clock=clock,
        event_sink=InMemoryDomainEventSink(),
    )
    verifier = StubVerifier(claims)
    federation = FederatedAuthenticationService(
        identity_repository=identities,
        authentication_service=authentication,
        token_verifier=verifier,
        assurance_resolver=StubAssuranceResolver(),
        clock=clock,
        session_ttl=timedelta(hours=8),
    )
    return federation, identities, sessions, verifier


def _linked_identity(
    identities: InMemoryIdentityRepository,
    *,
    subject: str = "external-user-42",
    email: str | None = "alice@example.com",
) -> Identity:
    identity = Identity.create_user(
        display_name="Alice",
        primary_email=None if email is None else EmailAddress.parse(email),
        created_at=NOW - timedelta(days=1),
    )
    identity.pull_events()
    identity.activate(at=NOW - timedelta(days=1) + timedelta(minutes=1))
    identity.pull_events()
    identity.link_external_identity(
        provider_id="entra-prod",
        external_subject=subject,
        at=NOW - timedelta(hours=1),
    )
    identity.pull_events()
    identities.save(identity)
    return identity


def test_federated_authentication_resolves_provider_subject_and_opens_oidc_session() -> None:
    federation, identities, sessions, verifier = _services(_claims())
    identity = _linked_identity(identities)

    session = federation.authenticate(
        "verified-id-token",
        expected_nonce="nonce-123",
        device_id="browser-1",
        network_zone="trusted",
    )

    assert verifier.expected_nonce == "nonce-123"
    assert session.identity_id == identity.id
    assert session.context.method is AuthenticationMethod.OIDC
    assert session.context.provider_id == "entra-prod"
    assert session.context.assurance_level is AssuranceLevel.AAL2
    assert session.context.mfa is True
    assert session.context.authenticated_at == NOW - timedelta(minutes=1)
    assert session.context.device_id == "browser-1"
    assert session.context.network_zone == "trusted"
    assert session.expires_at == NOW + timedelta(hours=8)
    assert sessions.get(session.id) == session


def test_verified_email_never_auto_links_a_different_external_subject() -> None:
    federation, identities, _, _ = _services(
        _claims(subject="new-subject", email="alice@example.com")
    )
    _linked_identity(
        identities,
        subject="old-subject",
        email="alice@example.com",
    )

    with pytest.raises(ExternalIdentityNotLinked):
        federation.authenticate("verified-id-token")


def test_unlinked_external_subject_is_denied() -> None:
    federation, _, _, _ = _services(_claims(subject="unknown"))

    with pytest.raises(ExternalIdentityNotLinked):
        federation.authenticate("verified-id-token")


def test_inactive_linked_identity_is_denied_by_local_authentication_policy() -> None:
    federation, identities, _, _ = _services(_claims())
    identity = _linked_identity(identities)
    loaded = identities.get(identity.id)
    assert loaded is not None
    loaded.disable(at=NOW, reason="security")
    loaded.pull_events()
    identities.save(loaded)

    with pytest.raises(AuthenticationSubjectInactive):
        federation.authenticate("verified-id-token")


def test_federation_requires_positive_local_session_ttl() -> None:
    clock = FrozenClock(NOW)
    claims = _claims()
    identities = InMemoryIdentityRepository()
    authentication = AuthenticationApplicationService(
        identity_repository=identities,
        credential_repository=InMemoryCredentialRepository(),
        session_repository=InMemorySessionRepository(),
        clock=clock,
        event_sink=InMemoryDomainEventSink(),
    )

    with pytest.raises(InvalidFederationPolicy):
        FederatedAuthenticationService(
            identity_repository=identities,
            authentication_service=authentication,
            token_verifier=StubVerifier(claims),
            assurance_resolver=StubAssuranceResolver(),
            clock=clock,
            session_ttl=timedelta(0),
        )
