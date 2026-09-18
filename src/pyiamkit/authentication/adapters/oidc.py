"""Static-key OpenID Connect ID Token verification adapter."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from secrets import compare_digest
from typing import cast
from urllib.parse import urlsplit

import jwt as pyjwt

from pyiamkit.shared import Clock

from ..domain.value_objects import AssuranceLevel
from ..federation import (
    FederatedAssurance,
    FederatedAssuranceResolver,
    FederatedIdentityClaims,
    IdentityTokenVerifier,
    InvalidIdentityToken,
)

OidcVerificationKey = str | bytes

_ALLOWED_ALGORITHMS = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
_REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat")


class OidcConfigurationError(InvalidIdentityToken):
    """Raised when an OIDC verifier is configured unsafely."""

    code = "OIDC_CONFIGURATION_INVALID"


class StaticOidcIdTokenVerifier(IdentityTokenVerifier):
    """Verify OIDC ID Tokens using configured issuer, audience and signing keys."""

    def __init__(
        self,
        *,
        provider_id: str,
        issuer: str,
        client_id: str,
        verification_key: OidcVerificationKey | None = None,
        verification_keys: Mapping[str, OidcVerificationKey] | None = None,
        algorithm: str = "RS256",
        clock: Clock,
        leeway: timedelta = timedelta(seconds=30),
    ) -> None:
        provider_id = provider_id.strip()
        issuer = issuer.strip()
        client_id = client_id.strip()
        algorithm = algorithm.strip()

        if not provider_id:
            raise OidcConfigurationError("provider_id must not be empty")
        _validate_issuer(issuer)
        if not client_id:
            raise OidcConfigurationError("client_id must not be empty")
        if algorithm not in _ALLOWED_ALGORITHMS:
            raise OidcConfigurationError(f"Unsupported OIDC signing algorithm: {algorithm!r}")
        if leeway < timedelta(0):
            raise OidcConfigurationError("leeway must not be negative")

        keys = {
            key_id.strip(): key
            for key_id, key in dict(verification_keys or {}).items()
            if key_id.strip()
        }
        if verification_key is None and not keys:
            raise OidcConfigurationError("At least one verification key is required")

        self._provider_id = provider_id
        self._issuer = issuer
        self._client_id = client_id
        self._verification_key = verification_key
        self._verification_keys = keys
        self._algorithm = algorithm
        self._clock = clock
        self._leeway = leeway

    def verify_identity_token(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> FederatedIdentityClaims:
        token = token.strip()
        if not token:
            raise InvalidIdentityToken("OIDC ID Token must not be empty")

        key = self._select_key(token)
        try:
            decoded = pyjwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=self._client_id,
                issuer=self._issuer,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except pyjwt.InvalidTokenError as exc:
            raise InvalidIdentityToken(
                "OIDC ID Token signature or registered claims are invalid"
            ) from exc

        payload = cast(dict[str, object], decoded)
        claims = self._parse_claims(payload)
        self._validate_time(claims)
        self._validate_nonce(claims, expected_nonce)
        self._validate_authorized_party(claims)
        return claims

    def _select_key(self, token: str) -> OidcVerificationKey:
        try:
            raw_header = pyjwt.get_unverified_header(token)
        except pyjwt.InvalidTokenError as exc:
            raise InvalidIdentityToken("OIDC ID Token header is invalid") from exc

        header = cast(dict[str, object], raw_header)
        if str(header.get("alg", "")) != self._algorithm:
            raise InvalidIdentityToken(
                "OIDC ID Token algorithm does not match configured algorithm"
            )

        if self._verification_keys:
            key_id = header.get("kid")
            if not isinstance(key_id, str) or not key_id.strip():
                raise InvalidIdentityToken("OIDC ID Token kid header is required")
            key = self._verification_keys.get(key_id.strip())
            if key is None:
                raise InvalidIdentityToken("OIDC ID Token kid is unknown")
            return key

        if self._verification_key is None:
            raise OidcConfigurationError("No OIDC verification key is available")
        return self._verification_key

    def _parse_claims(self, payload: Mapping[str, object]) -> FederatedIdentityClaims:
        audiences = _audiences(payload)
        subject = _subject(payload)
        auth_time = _optional_numeric_date(payload, "auth_time")
        nonce = _optional_text(payload, "nonce")
        authorized_party = _optional_text(payload, "azp")
        acr = _optional_text(payload, "acr")
        amr = _amr(payload)
        email = _optional_text(payload, "email")
        email_verified = _optional_bool(payload, "email_verified")

        try:
            return FederatedIdentityClaims(
                provider_id=self._provider_id,
                issuer=_required_text(payload, "iss"),
                subject=subject,
                audiences=audiences,
                issued_at=_numeric_date(payload, "iat"),
                expires_at=_numeric_date(payload, "exp"),
                auth_time=auth_time,
                nonce=nonce,
                authorized_party=authorized_party,
                acr=acr,
                amr=amr,
                email=email,
                email_verified=email_verified,
            )
        except ValueError as exc:
            raise InvalidIdentityToken("OIDC ID Token contains invalid claims") from exc

    def _validate_time(self, claims: FederatedIdentityClaims) -> None:
        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise OidcConfigurationError("Clock must return UTC-aware datetimes")
        if now >= claims.expires_at + self._leeway:
            raise InvalidIdentityToken("OIDC ID Token has expired")
        if claims.issued_at > now + self._leeway:
            raise InvalidIdentityToken("OIDC ID Token was issued in the future")
        if claims.auth_time is not None and claims.auth_time > now + self._leeway:
            raise InvalidIdentityToken("OIDC auth_time is in the future")

    @staticmethod
    def _validate_nonce(
        claims: FederatedIdentityClaims,
        expected_nonce: str | None,
    ) -> None:
        if expected_nonce is None:
            return
        expected = expected_nonce.strip()
        if not expected:
            raise InvalidIdentityToken("Expected OIDC nonce must not be empty")
        if claims.nonce is None or not compare_digest(claims.nonce, expected):
            raise InvalidIdentityToken("OIDC nonce does not match the authentication request")

    def _validate_authorized_party(self, claims: FederatedIdentityClaims) -> None:
        if len(claims.audiences) > 1:
            if claims.authorized_party is None:
                raise InvalidIdentityToken(
                    "OIDC azp is required when the ID Token has multiple audiences"
                )
            if claims.authorized_party != self._client_id:
                raise InvalidIdentityToken("OIDC azp does not match client_id")
        elif claims.authorized_party is not None and claims.authorized_party != self._client_id:
            raise InvalidIdentityToken("OIDC azp does not match client_id")


class StaticOidcAssuranceResolver(FederatedAssuranceResolver):
    """Map configured OIDC ACR/AMR values into PyIAMKit assurance semantics."""

    def __init__(
        self,
        *,
        acr_mapping: Mapping[str, AssuranceLevel] | None = None,
        mfa_amr_values: tuple[str, ...] = (),
        default_assurance: AssuranceLevel = AssuranceLevel.AAL1,
    ) -> None:
        self._acr_mapping = {
            key.strip(): value for key, value in dict(acr_mapping or {}).items() if key.strip()
        }
        self._mfa_amr_values = frozenset(
            value.strip() for value in mfa_amr_values if value.strip()
        )
        self._default_assurance = default_assurance

    def resolve(self, claims: FederatedIdentityClaims) -> FederatedAssurance:
        level = (
            self._default_assurance
            if claims.acr is None
            else self._acr_mapping.get(claims.acr, self._default_assurance)
        )
        mfa = bool(self._mfa_amr_values.intersection(claims.amr))
        return FederatedAssurance(level=level, mfa=mfa)


def _validate_issuer(issuer: str) -> None:
    if not issuer:
        raise OidcConfigurationError("issuer must not be empty")
    parsed = urlsplit(issuer)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
    ):
        raise OidcConfigurationError(
            "issuer must be an HTTPS URL without query or fragment"
        )


def _required_text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise InvalidIdentityToken(f"OIDC {name} claim is invalid")
    return value.strip()


def _optional_text(payload: Mapping[str, object], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InvalidIdentityToken(f"OIDC {name} claim is invalid")
    return value.strip()


def _optional_bool(payload: Mapping[str, object], name: str) -> bool | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise InvalidIdentityToken(f"OIDC {name} claim must be boolean")
    return value


def _subject(payload: Mapping[str, object]) -> str:
    subject = _required_text(payload, "sub")
    try:
        encoded = subject.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidIdentityToken("OIDC sub must contain ASCII characters only") from exc
    if len(encoded) > 255:
        raise InvalidIdentityToken("OIDC sub must not exceed 255 ASCII characters")
    return subject


def _audiences(payload: Mapping[str, object]) -> tuple[str, ...]:
    value = payload.get("aud")
    if isinstance(value, str):
        audiences = (value.strip(),)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        audiences = tuple(item.strip() for item in cast(list[str], value))
    else:
        raise InvalidIdentityToken("OIDC aud claim is invalid")
    if not audiences or any(not item for item in audiences):
        raise InvalidIdentityToken("OIDC aud claim is invalid")
    return audiences


def _amr(payload: Mapping[str, object]) -> tuple[str, ...]:
    value = payload.get("amr")
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InvalidIdentityToken("OIDC amr claim must be a list of strings")
    values = tuple(item.strip() for item in cast(list[str], value))
    if any(not item for item in values):
        raise InvalidIdentityToken("OIDC amr claim contains an empty value")
    return values


def _numeric_date(payload: Mapping[str, object], name: str) -> datetime:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidIdentityToken(f"OIDC {name} claim must be a NumericDate")
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise InvalidIdentityToken(f"OIDC {name} claim is out of range") from exc


def _optional_numeric_date(
    payload: Mapping[str, object],
    name: str,
) -> datetime | None:
    if payload.get(name) is None:
        return None
    return _numeric_date(payload, name)
