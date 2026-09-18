"""Framework-neutral access-token contracts for Authentication."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from pyiamkit.identity import IdentityId
from pyiamkit.shared import EntityId

from .domain.errors import AuthenticationError
from .domain.value_objects import AssuranceLevel, AuthenticationMethod, SessionId


class TokenId(EntityId):
    """Opaque JWT identifier used for the jti claim."""


class TokenType(StrEnum):
    ACCESS = "access"


class TokenError(AuthenticationError):
    """Base token error."""


class TokenConfigurationError(TokenError):
    """Raised when a token adapter is configured unsafely or inconsistently."""


class InvalidAccessToken(TokenError):
    """Raised when an access token cannot be trusted."""


class ExpiredAccessToken(InvalidAccessToken):
    """Raised when an otherwise valid access token has expired."""


class TokenSessionInactive(InvalidAccessToken):
    """Raised when the Session referenced by a token is unavailable or inactive."""


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    issuer: str
    subject_id: IdentityId
    audiences: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    token_id: TokenId
    session_id: SessionId
    auth_time: datetime
    assurance_level: AssuranceLevel
    authentication_method: AuthenticationMethod
    mfa: bool

    def __post_init__(self) -> None:
        issuer = self.issuer.strip()
        if not issuer:
            raise ValueError("issuer must not be empty")
        audiences = tuple(item.strip() for item in self.audiences if item.strip())
        if not audiences:
            raise ValueError("at least one audience is required")
        if len(set(audiences)) != len(audiences):
            raise ValueError("audiences must be unique")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audiences", audiences)

        for name, value in (
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
            ("auth_time", self.auth_time),
        ):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"{name} must be UTC-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.auth_time > self.issued_at:
            raise ValueError("auth_time must not be after issued_at")


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    token: str
    claims: AccessTokenClaims

    def __post_init__(self) -> None:
        token = self.token.strip()
        if not token:
            raise ValueError("token must not be empty")
        object.__setattr__(self, "token", token)
