"""Authentication identifiers, lifecycle states and assurance values."""

from enum import StrEnum

from pyiamkit.shared import EntityId


class CredentialId(EntityId):
    """Opaque credential identifier."""


class SessionId(EntityId):
    """Opaque authentication-session identifier."""


class MfaFactorId(EntityId):
    """Opaque multi-factor enrollment identifier."""


class CredentialType(StrEnum):
    PASSWORD = "password"  # nosec B105
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    PASSKEY = "passkey"
    CLIENT_SECRET = "client_secret"  # nosec B105
    EXTERNAL = "external"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SessionStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class MfaFactorType(StrEnum):
    TOTP = "totp"


class MfaFactorStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class AuthenticationMethod(StrEnum):
    PASSWORD = "password"  # nosec B105
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    PASSKEY = "passkey"
    OIDC = "oidc"
    SAML = "saml"
    EXTERNAL = "external"


class AssuranceLevel(StrEnum):
    AAL1 = "aal1"
    AAL2 = "aal2"
    AAL3 = "aal3"
