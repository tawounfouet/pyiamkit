"""OIDC Discovery and remote JWKS infrastructure adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Protocol, cast
from urllib.parse import urlsplit

import httpx
import jwt as pyjwt

from pyiamkit.shared import Clock

from ..federation import FederatedIdentityClaims, InvalidFederationPolicy, InvalidIdentityToken
from .oidc import OidcConfigurationError, StaticOidcIdTokenVerifier


class OidcDiscoveryError(InvalidFederationPolicy):
    """Raised when provider discovery metadata is invalid or unsafe."""

    code = "OIDC_DISCOVERY_INVALID"


class OidcRemoteError(InvalidFederationPolicy):
    """Raised when remote OIDC metadata or keys cannot be retrieved safely."""

    code = "OIDC_REMOTE_ERROR"


class OidcJwksError(InvalidFederationPolicy):
    """Raised when a remote JWKS document is invalid or unsafe."""

    code = "OIDC_JWKS_INVALID"


@dataclass(frozen=True, slots=True)
class OidcProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    id_token_signing_algorithms: tuple[str, ...]
    userinfo_endpoint: str | None = None

    def __post_init__(self) -> None:
        _require_https_url(self.issuer, name="issuer", allow_query=False)
        _require_https_url(
            self.authorization_endpoint,
            name="authorization_endpoint",
            allow_query=True,
        )
        _require_https_url(
            self.token_endpoint,
            name="token_endpoint",
            allow_query=True,
        )
        _require_https_url(self.jwks_uri, name="jwks_uri", allow_query=True)

        algorithms = tuple(
            algorithm.strip() for algorithm in self.id_token_signing_algorithms if algorithm.strip()
        )
        if not algorithms:
            raise OidcDiscoveryError("id_token_signing_alg_values_supported must not be empty")
        if len(set(algorithms)) != len(algorithms):
            raise OidcDiscoveryError("id_token_signing_alg_values_supported must be unique")
        object.__setattr__(self, "id_token_signing_algorithms", algorithms)

        if self.userinfo_endpoint is not None:
            endpoint = self.userinfo_endpoint.strip()
            if endpoint:
                _require_https_url(endpoint, name="userinfo_endpoint", allow_query=True)
                object.__setattr__(self, "userinfo_endpoint", endpoint)
            else:
                object.__setattr__(self, "userinfo_endpoint", None)


class OidcJsonTransport(Protocol):
    """Minimal JSON transport contract used by Discovery/JWKS adapters."""

    def get_json(self, url: str) -> Mapping[str, object]: ...


class HttpxOidcTransport:
    """Small synchronous HTTPX transport with redirects disabled by default."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        if timeout <= 0:
            raise OidcRemoteError("HTTP timeout must be positive")
        self._owns_client = client is None
        self._client = (
            httpx.Client(timeout=timeout, follow_redirects=False) if client is None else client
        )

    def get_json(self, url: str) -> Mapping[str, object]:
        _require_https_url(url, name="remote OIDC URL", allow_query=True)
        try:
            response = self._client.get(
                url,
                headers={"Accept": "application/json, application/jwk-set+json"},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OidcRemoteError(f"OIDC remote request failed for {url!r}") from exc

        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type not in {"application/json", "application/jwk-set+json"}:
            raise OidcRemoteError(
                f"OIDC remote response from {url!r} is not a supported JSON media type"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise OidcRemoteError(f"OIDC remote response from {url!r} is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise OidcRemoteError(f"OIDC remote response from {url!r} must be a JSON object")
        return cast(dict[str, object], payload)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpxOidcTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class OidcDiscoveryClient:
    """Resolve and cache validated OpenID Provider metadata."""

    def __init__(
        self,
        *,
        transport: OidcJsonTransport,
        clock: Clock,
        cache_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        if cache_ttl <= timedelta(0):
            raise OidcDiscoveryError("Discovery cache_ttl must be positive")
        self._transport = transport
        self._clock = clock
        self._cache_ttl = cache_ttl
        self._cache: dict[str, tuple[OidcProviderMetadata, datetime]] = {}
        self._lock = RLock()

    def discover(self, issuer: str) -> OidcProviderMetadata:
        configured_issuer = issuer.strip()
        _require_https_url(configured_issuer, name="issuer", allow_query=False)
        now = _utc_now(self._clock)

        with self._lock:
            cached = self._cache.get(configured_issuer)
            if cached is not None and now < cached[1]:
                return cached[0]

            discovery_url = configured_issuer.rstrip("/") + "/.well-known/openid-configuration"
            payload = self._transport.get_json(discovery_url)
            metadata = _metadata_from_payload(
                payload,
                configured_issuer=configured_issuer,
            )
            self._cache[configured_issuer] = (
                metadata,
                now + self._cache_ttl,
            )
            return metadata


class JwksKeyResolver:
    """Cache public signing keys and refresh once for an unknown kid."""

    _PRIVATE_OR_SYMMETRIC_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

    def __init__(
        self,
        *,
        jwks_uri: str,
        transport: OidcJsonTransport,
        clock: Clock,
        algorithm: str,
        cache_ttl: timedelta = timedelta(minutes=5),
        unknown_kid_refresh_cooldown: timedelta = timedelta(seconds=30),
    ) -> None:
        _require_https_url(jwks_uri, name="jwks_uri", allow_query=True)
        if not algorithm.strip():
            raise OidcJwksError("algorithm must not be empty")
        if cache_ttl <= timedelta(0):
            raise OidcJwksError("JWKS cache_ttl must be positive")
        if unknown_kid_refresh_cooldown < timedelta(0):
            raise OidcJwksError("unknown_kid_refresh_cooldown must not be negative")

        self._jwks_uri = jwks_uri.strip()
        self._transport = transport
        self._clock = clock
        self._algorithm = algorithm.strip()
        self._cache_ttl = cache_ttl
        self._cooldown = unknown_kid_refresh_cooldown
        self._keys: dict[str, pyjwt.PyJWK] = {}
        self._expires_at: datetime | None = None
        self._last_refresh_at: datetime | None = None
        self._lock = RLock()

    def resolve(self, key_id: str) -> pyjwt.PyJWK:
        kid = key_id.strip()
        if not kid:
            raise InvalidIdentityToken("OIDC ID Token kid header is required")

        now = _utc_now(self._clock)
        with self._lock:
            if self._expires_at is None or now >= self._expires_at:
                self._refresh(now)

            key = self._keys.get(kid)
            if key is not None:
                return key

            if self._may_force_refresh(now):
                self._refresh(now)
                key = self._keys.get(kid)
                if key is not None:
                    return key

            raise InvalidIdentityToken("OIDC ID Token kid is unknown")

    def _may_force_refresh(self, now: datetime) -> bool:
        if self._last_refresh_at is None:
            return True
        return now >= self._last_refresh_at + self._cooldown

    def _refresh(self, now: datetime) -> None:
        payload = self._transport.get_json(self._jwks_uri)
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list):
            raise OidcJwksError("JWKS keys must be a JSON array")

        parsed: dict[str, pyjwt.PyJWK] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise OidcJwksError("Every JWKS key must be a JSON object")
            jwk = cast(dict[str, object], raw_key)
            self._reject_secret_material(jwk)

            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid.strip():
                continue
            use = jwk.get("use")
            if use is not None and use != "sig":
                continue
            advertised_algorithm = jwk.get("alg")
            if advertised_algorithm is not None and advertised_algorithm != self._algorithm:
                continue

            try:
                parsed_key = pyjwt.PyJWK.from_dict(
                    jwk,
                    algorithm=self._algorithm,
                )
            except (pyjwt.InvalidKeyError, ValueError, TypeError) as exc:
                raise OidcJwksError(f"JWKS key {kid!r} is invalid") from exc
            parsed[kid.strip()] = parsed_key

        if not parsed:
            raise OidcJwksError("JWKS does not contain a usable public signing key")

        self._keys = parsed
        self._last_refresh_at = now
        self._expires_at = now + self._cache_ttl

    @classmethod
    def _reject_secret_material(cls, jwk: Mapping[str, object]) -> None:
        key_type = jwk.get("kty")
        if key_type == "oct":
            raise OidcJwksError("Remote JWKS must not expose symmetric keys")
        exposed = cls._PRIVATE_OR_SYMMETRIC_FIELDS.intersection(jwk)
        if exposed:
            field_names = ", ".join(sorted(exposed))
            raise OidcJwksError(
                f"Remote JWKS exposes private or symmetric key material: {field_names}"
            )


class DiscoveredOidcIdTokenVerifier:
    """OIDC verifier backed by validated Discovery metadata and cached JWKS."""

    def __init__(
        self,
        *,
        provider_id: str,
        issuer: str,
        client_id: str,
        algorithm: str,
        transport: OidcJsonTransport,
        clock: Clock,
        leeway: timedelta = timedelta(seconds=30),
        metadata_cache_ttl: timedelta = timedelta(hours=1),
        jwks_cache_ttl: timedelta = timedelta(minutes=5),
        unknown_kid_refresh_cooldown: timedelta = timedelta(seconds=30),
    ) -> None:
        provider_id = provider_id.strip()
        issuer = issuer.strip()
        client_id = client_id.strip()
        algorithm = algorithm.strip()

        if not provider_id:
            raise OidcConfigurationError("provider_id must not be empty")
        _require_https_url(issuer, name="issuer", allow_query=False)
        if not client_id:
            raise OidcConfigurationError("client_id must not be empty")
        if not algorithm:
            raise OidcConfigurationError("algorithm must not be empty")
        if leeway < timedelta(0):
            raise OidcConfigurationError("leeway must not be negative")

        self._provider_id = provider_id
        self._issuer = issuer
        self._client_id = client_id
        self._algorithm = algorithm
        self._transport = transport
        self._clock = clock
        self._leeway = leeway
        self._discovery = OidcDiscoveryClient(
            transport=transport,
            clock=clock,
            cache_ttl=metadata_cache_ttl,
        )
        self._jwks_cache_ttl = jwks_cache_ttl
        self._unknown_kid_refresh_cooldown = unknown_kid_refresh_cooldown
        self._resolver: JwksKeyResolver | None = None
        self._resolver_uri: str | None = None
        self._lock = RLock()

    def verify_identity_token(
        self,
        token: str,
        *,
        expected_nonce: str | None = None,
    ) -> FederatedIdentityClaims:
        metadata = self._discovery.discover(self._issuer)
        if self._algorithm not in metadata.id_token_signing_algorithms:
            raise OidcConfigurationError(
                f"Configured algorithm {self._algorithm!r} is not advertised by provider metadata"
            )

        kid = _token_key_id(token, expected_algorithm=self._algorithm)
        resolver = self._resolver_for(metadata.jwks_uri)
        key = resolver.resolve(kid)

        verifier = StaticOidcIdTokenVerifier(
            provider_id=self._provider_id,
            issuer=self._issuer,
            client_id=self._client_id,
            verification_key=key,
            algorithm=self._algorithm,
            clock=self._clock,
            leeway=self._leeway,
        )
        return verifier.verify_identity_token(
            token,
            expected_nonce=expected_nonce,
        )

    def _resolver_for(self, jwks_uri: str) -> JwksKeyResolver:
        with self._lock:
            if self._resolver is None or self._resolver_uri != jwks_uri:
                self._resolver = JwksKeyResolver(
                    jwks_uri=jwks_uri,
                    transport=self._transport,
                    clock=self._clock,
                    algorithm=self._algorithm,
                    cache_ttl=self._jwks_cache_ttl,
                    unknown_kid_refresh_cooldown=self._unknown_kid_refresh_cooldown,
                )
                self._resolver_uri = jwks_uri
            return self._resolver


def _metadata_from_payload(
    payload: Mapping[str, object],
    *,
    configured_issuer: str,
) -> OidcProviderMetadata:
    issuer = _required_string(payload, "issuer")
    if issuer != configured_issuer:
        raise OidcDiscoveryError("Discovered issuer must exactly match the configured issuer")

    algorithms_value = payload.get("id_token_signing_alg_values_supported")
    if not isinstance(algorithms_value, list) or not all(
        isinstance(item, str) for item in algorithms_value
    ):
        raise OidcDiscoveryError(
            "id_token_signing_alg_values_supported must be an array of strings"
        )
    algorithms = tuple(item.strip() for item in cast(list[str], algorithms_value) if item.strip())

    return OidcProviderMetadata(
        issuer=issuer,
        authorization_endpoint=_required_string(payload, "authorization_endpoint"),
        token_endpoint=_required_string(payload, "token_endpoint"),
        jwks_uri=_required_string(payload, "jwks_uri"),
        id_token_signing_algorithms=algorithms,
        userinfo_endpoint=_optional_string(payload, "userinfo_endpoint"),
    )


def _token_key_id(token: str, *, expected_algorithm: str) -> str:
    compact = token.strip()
    if not compact:
        raise InvalidIdentityToken("OIDC ID Token must not be empty")
    try:
        raw_header = pyjwt.get_unverified_header(compact)
    except pyjwt.InvalidTokenError as exc:
        raise InvalidIdentityToken("OIDC ID Token header is invalid") from exc

    header = cast(dict[str, object], raw_header)
    if str(header.get("alg", "")) != expected_algorithm:
        raise InvalidIdentityToken("OIDC ID Token algorithm does not match configured algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise InvalidIdentityToken("OIDC ID Token kid header is required")
    return kid.strip()


def _required_string(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise OidcDiscoveryError(f"Discovery {name} must be a non-empty string")
    return value.strip()


def _optional_string(payload: Mapping[str, object], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise OidcDiscoveryError(f"Discovery {name} must be a non-empty string")
    return value.strip()


def _require_https_url(
    url: str,
    *,
    name: str,
    allow_query: bool,
) -> None:
    value = url.strip()
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise OidcDiscoveryError(f"{name} must be an HTTPS URL without a fragment")
    if not allow_query and parsed.query:
        raise OidcDiscoveryError(f"{name} must not contain a query string")


def _utc_now(clock: Clock) -> datetime:
    now = clock.now()
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise OidcConfigurationError("Clock must return UTC-aware datetimes")
    return now
