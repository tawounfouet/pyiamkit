"""PyJWT access-token adapter bound to durable Authentication Sessions."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast

import jwt as pyjwt

from pyiamkit.identity import IdentityId
from pyiamkit.shared import Clock

from ..domain.session import Session
from ..domain.value_objects import AssuranceLevel, AuthenticationMethod, SessionId
from ..ports import SessionRepository
from ..tokens import (
    AccessTokenClaims,
    ExpiredAccessToken,
    InvalidAccessToken,
    IssuedAccessToken,
    TokenConfigurationError,
    TokenId,
    TokenSessionInactive,
    TokenType,
)

JwtKey = str | bytes

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
_REQUIRED_CLAIMS = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "sid",
    "auth_time",
    "aal",
    "auth_method",
    "mfa",
    "token_use",
)


class JwtTokenProvider:
    """Issue and verify access JWTs while keeping Session state authoritative."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str | tuple[str, ...],
        signing_key: JwtKey,
        session_repository: SessionRepository,
        clock: Clock,
        verification_key: JwtKey | None = None,
        verification_keys: Mapping[str, JwtKey] | None = None,
        key_id: str | None = None,
        algorithm: str = "RS256",
        access_token_ttl: timedelta = timedelta(minutes=15),
        leeway: timedelta = timedelta(seconds=30),
    ) -> None:
        normalized_issuer = issuer.strip()
        if not normalized_issuer:
            raise TokenConfigurationError("issuer must not be empty")

        audiences = (audience,) if isinstance(audience, str) else audience
        normalized_audiences = tuple(item.strip() for item in audiences if item.strip())
        if not normalized_audiences:
            raise TokenConfigurationError("at least one audience is required")
        if len(set(normalized_audiences)) != len(normalized_audiences):
            raise TokenConfigurationError("audiences must be unique")

        normalized_algorithm = algorithm.strip()
        if normalized_algorithm not in _ALLOWED_ALGORITHMS:
            raise TokenConfigurationError(
                f"Unsupported or unsafe JWT algorithm: {normalized_algorithm!r}"
            )
        if not signing_key:
            raise TokenConfigurationError("signing_key must not be empty")
        if access_token_ttl <= timedelta(0):
            raise TokenConfigurationError("access_token_ttl must be positive")
        if leeway < timedelta(0):
            raise TokenConfigurationError("leeway must not be negative")

        normalized_key_id = None if key_id is None else key_id.strip() or None
        key_set = {
            candidate.strip(): key
            for candidate, key in dict(verification_keys or {}).items()
            if candidate.strip()
        }
        if key_set and normalized_key_id is None:
            raise TokenConfigurationError(
                "key_id is required when verification_keys are configured"
            )
        if normalized_key_id is not None and key_set and normalized_key_id not in key_set:
            key_set[normalized_key_id] = verification_key or signing_key

        self._issuer = normalized_issuer
        self._audiences = normalized_audiences
        self._signing_key = signing_key
        self._verification_key = verification_key or signing_key
        self._verification_keys = key_set
        self._key_id = normalized_key_id
        self._algorithm = normalized_algorithm
        self._ttl = access_token_ttl
        self._leeway = leeway
        self._sessions = session_repository
        self._clock = clock

    def issue_access_token(self, session: Session) -> IssuedAccessToken:
        now = _second_precision(self._clock.now())
        if not session.is_active(at=now):
            raise TokenSessionInactive(f"Session {session.id} is not active")

        session_expires_at = _second_precision(session.expires_at)
        expires_at = min(now + self._ttl, session_expires_at)
        if expires_at <= now:
            raise TokenSessionInactive(f"Session {session.id} cannot issue a live token")

        claims = AccessTokenClaims(
            issuer=self._issuer,
            subject_id=session.identity_id,
            audiences=self._audiences,
            issued_at=now,
            expires_at=expires_at,
            token_id=TokenId.new(),
            session_id=session.id,
            auth_time=_second_precision(session.context.authenticated_at),
            assurance_level=session.context.assurance_level,
            authentication_method=session.context.method,
            mfa=session.context.mfa,
        )
        payload: dict[str, object] = {
            "iss": claims.issuer,
            "sub": str(claims.subject_id),
            "aud": list(claims.audiences),
            "exp": int(claims.expires_at.timestamp()),
            "iat": int(claims.issued_at.timestamp()),
            "jti": str(claims.token_id),
            "sid": str(claims.session_id),
            "auth_time": int(claims.auth_time.timestamp()),
            "aal": claims.assurance_level.value,
            "auth_method": claims.authentication_method.value,
            "mfa": claims.mfa,
            "amr": _authentication_methods(claims),
            "token_use": TokenType.ACCESS.value,
        }
        headers: dict[str, str] = {"typ": "JWT"}
        if self._key_id is not None:
            headers["kid"] = self._key_id

        token = pyjwt.encode(
            payload,
            self._signing_key,
            algorithm=self._algorithm,
            headers=headers,
        )
        return IssuedAccessToken(token=token, claims=claims)

    def verify_access_token(self, token: str) -> AccessTokenClaims:
        token = token.strip()
        if not token:
            raise InvalidAccessToken("Token must not be empty")

        key = self._select_verification_key(token)
        try:
            decoded = pyjwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=self._audiences,
                issuer=self._issuer,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except pyjwt.InvalidTokenError as exc:
            raise InvalidAccessToken("JWT signature or registered claims are invalid") from exc

        payload = cast(dict[str, object], decoded)
        claims = _claims_from_payload(payload)
        self._validate_time(claims)
        self._validate_session(claims)
        return claims

    def _select_verification_key(self, token: str) -> JwtKey:
        try:
            raw_header = pyjwt.get_unverified_header(token)
        except pyjwt.InvalidTokenError as exc:
            raise InvalidAccessToken("JWT header is invalid") from exc
        header = cast(dict[str, object], raw_header)

        if str(header.get("alg", "")) != self._algorithm:
            raise InvalidAccessToken("JWT algorithm does not match configured algorithm")
        token_type = header.get("typ")
        if token_type is not None and str(token_type).upper() != "JWT":
            raise InvalidAccessToken("JWT typ header is invalid")

        if not self._verification_keys:
            return self._verification_key

        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id.strip():
            raise InvalidAccessToken("JWT kid header is required")
        key = self._verification_keys.get(key_id.strip())
        if key is None:
            raise InvalidAccessToken("JWT kid is unknown")
        return key

    def _validate_time(self, claims: AccessTokenClaims) -> None:
        now = self._clock.now()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise TokenConfigurationError("Clock must return UTC-aware datetimes")
        if now >= claims.expires_at + self._leeway:
            raise ExpiredAccessToken("JWT has expired")
        if claims.issued_at > now + self._leeway:
            raise InvalidAccessToken("JWT was issued in the future")

    def _validate_session(self, claims: AccessTokenClaims) -> None:
        now = self._clock.now()
        session = self._sessions.get(claims.session_id)
        if session is None or not session.is_active(at=now):
            raise TokenSessionInactive(f"Session {claims.session_id} is not active")
        if session.identity_id != claims.subject_id:
            raise InvalidAccessToken("JWT subject does not match Session subject")
        if claims.expires_at > _second_precision(session.expires_at):
            raise InvalidAccessToken("JWT expiration exceeds Session expiration")
        if session.context.assurance_level is not claims.assurance_level:
            raise InvalidAccessToken("JWT assurance level does not match Session")
        if session.context.method is not claims.authentication_method:
            raise InvalidAccessToken("JWT authentication method does not match Session")
        if session.context.mfa is not claims.mfa:
            raise InvalidAccessToken("JWT MFA state does not match Session")
        if _second_precision(session.context.authenticated_at) != claims.auth_time:
            raise InvalidAccessToken("JWT auth_time does not match Session")


def _claims_from_payload(payload: Mapping[str, object]) -> AccessTokenClaims:
    if payload.get("token_use") != TokenType.ACCESS.value:
        raise InvalidAccessToken("JWT is not an access token")

    audience_value = payload.get("aud")
    if isinstance(audience_value, str):
        audiences = (audience_value,)
    elif isinstance(audience_value, list) and all(isinstance(item, str) for item in audience_value):
        audiences = tuple(cast(list[str], audience_value))
    else:
        raise InvalidAccessToken("JWT aud claim is invalid")

    mfa_value = payload.get("mfa")
    if not isinstance(mfa_value, bool):
        raise InvalidAccessToken("JWT mfa claim is invalid")

    try:
        return AccessTokenClaims(
            issuer=_required_text(payload, "iss"),
            subject_id=_identity_id(payload),
            audiences=audiences,
            issued_at=_numeric_date(payload, "iat"),
            expires_at=_numeric_date(payload, "exp"),
            token_id=TokenId.parse(_required_text(payload, "jti")),
            session_id=SessionId.parse(_required_text(payload, "sid")),
            auth_time=_numeric_date(payload, "auth_time"),
            assurance_level=AssuranceLevel(_required_text(payload, "aal")),
            authentication_method=AuthenticationMethod(_required_text(payload, "auth_method")),
            mfa=mfa_value,
        )
    except (TypeError, ValueError) as exc:
        raise InvalidAccessToken("JWT contains invalid Authentication claims") from exc


def _identity_id(payload: Mapping[str, object]) -> IdentityId:
    return IdentityId.parse(_required_text(payload, "sub"))


def _required_text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise InvalidAccessToken(f"JWT {name} claim is invalid")
    return value.strip()


def _numeric_date(payload: Mapping[str, object], name: str) -> datetime:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidAccessToken(f"JWT {name} claim must be a NumericDate")
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise InvalidAccessToken(f"JWT {name} claim is out of range") from exc


def _authentication_methods(claims: AccessTokenClaims) -> list[str]:
    methods = [claims.authentication_method.value]
    if claims.mfa:
        methods.append("mfa")
    return methods


def _second_precision(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise TokenConfigurationError("JWT timestamps must be UTC-aware")
    return datetime.fromtimestamp(int(value.timestamp()), tz=UTC)
