"""Framework-neutral external identity federation contracts and orchestration."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from pyiamkit.identity import IdentityRepository
from pyiamkit.shared import Clock

from .application import AuthenticationApplicationService
from .domain.errors import AuthenticationError
from .domain.session import Session
from .domain.value_objects import AssuranceLevel, AuthenticationMethod


class FederationError(AuthenticationError):
    """Base external federation error."""

    code = "FEDERATION_ERROR"


class InvalidIdentityToken(FederationError):
    """Raised when an external identity token cannot be trusted."""

    code = "FEDERATION_ID_TOKEN_INVALID"


class ExternalIdentityNotLinked(FederationError):
    """Raised when a verified external subject has no internal Identity link."""

    code = "FEDERATION_EXTERNAL_IDENTITY_NOT_LINKED"

    def __init__(self, provider_id: str, subject: str) -> None:
        super().__init__(
            f"External subject {subject!r} from provider {provider_id!r} is not linked."
        )


class InvalidFederationPolicy(FederationError):
    """Raised when local federation policy is invalid."""

    code = "FEDERATION_POLICY_INVALID"


@dataclass(frozen=True, slots=True)
class FederatedIdentityClaims:
    """Verified external identity facts, independent from a provider SDK."""

    provider_id: str
    issuer: str
    subject: str
    audiences: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    auth_time: datetime | None = None
    nonce: str | None = None
    authorized_party: str | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()
    email: str | None = None
    email_verified: bool | None = None

    def __post_init__(self) -> None:
        provider_id = self.provider_id.strip()
        issuer = self.issuer.strip()
        subject = self.subject.strip()
        audiences = tuple(item.strip() for item in self.audiences if item.strip())
        amr = tuple(item.strip() for item in self.amr if item.strip())

        if not provider_id:
            raise ValueError("provider_id must not be empty")
        if not issuer:
            raise ValueError("issuer must not be empty")
        if not subject:
            raise ValueError("subject must not be empty")
        if not audiences:
            raise ValueError("at least one audience is required")
        if len(set(audiences)) != len(audiences):
            raise ValueError("audiences must be unique")
        if len(set(amr)) != len(amr):
            raise ValueError("amr values must be unique")

        for name, value in (
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
            ("auth_time", self.auth_time),
        ):
            if value is None:
                continue
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")

        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.auth_time is not None and self.auth_time > self.issued_at:
            raise ValueError("auth_time must not be after issued_at")

        object.__setattr__(self, "provider_id", provider_id)
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "audiences", audiences)
        object.__setattr__(self, "amr", amr)

        for field_name in ("nonce", "authorized_party", "acr", "email"):
            value = getattr(self, field_name)
            if value is not None:
                normalized = value.strip()
                object.__setattr__(self, field_name, normalized or None)


@dataclass(frozen=True, slots=True)
class FederatedAssurance:
    """Local assurance interpretation of trusted external authentication claims."""

    level: AssuranceLevel
    mfa: bool


class IdentityTokenVerifier(Protocol):
    """Verify an external identity token into framework-neutral claims."""

    def verify_identity_token(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> FederatedIdentityClaims: ...


class FederatedAssuranceResolver(Protocol):
    """Map provider-specific ACR/AMR into local assurance semantics."""

    def resolve(self, claims: FederatedIdentityClaims) -> FederatedAssurance: ...


class FederatedAuthenticationService:
    """Resolve a verified external subject and establish a local Session."""

    def __init__(
        self,
        *,
        identity_repository: IdentityRepository,
        authentication_service: AuthenticationApplicationService,
        token_verifier: IdentityTokenVerifier,
        assurance_resolver: FederatedAssuranceResolver,
        clock: Clock,
        session_ttl: timedelta = timedelta(hours=8),
    ) -> None:
        if session_ttl <= timedelta(0):
            raise InvalidFederationPolicy("session_ttl must be positive")
        self._identities = identity_repository
        self._authentication = authentication_service
        self._verifier = token_verifier
        self._assurance = assurance_resolver
        self._clock = clock
        self._session_ttl = session_ttl

    def authenticate(
        self,
        identity_token: str,
        *,
        expected_nonce: str | None = None,
        device_id: str | None = None,
        network_zone: str | None = None,
    ) -> Session:
        claims = self._verifier.verify_identity_token(
            identity_token,
            expected_nonce=expected_nonce,
        )
        identity = self._identities.find_by_external_subject(
            claims.provider_id,
            claims.subject,
        )
        if identity is None:
            raise ExternalIdentityNotLinked(claims.provider_id, claims.subject)

        assurance = self._assurance.resolve(claims)
        now = self._clock.now()
        authenticated_at = claims.auth_time or claims.issued_at
        return self._authentication.open_session(
            identity_id=identity.id,
            method=AuthenticationMethod.OIDC,
            assurance_level=assurance.level,
            mfa=assurance.mfa,
            expires_at=now + self._session_ttl,
            authenticated_at=authenticated_at,
            provider_id=claims.provider_id,
            device_id=device_id,
            network_zone=network_zone,
        )
