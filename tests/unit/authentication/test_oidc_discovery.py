import base64
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pyiamkit.authentication import InvalidIdentityToken
from pyiamkit.authentication.adapters.oidc import OidcConfigurationError
from pyiamkit.authentication.adapters.oidc_discovery import (
    DiscoveredOidcIdTokenVerifier,
    HttpxOidcTransport,
    JwksKeyResolver,
    OidcDiscoveryClient,
    OidcDiscoveryError,
    OidcJwksError,
    OidcRemoteError,
)

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
ISSUER = "https://idp.example.com/tenant"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
JWKS_URI = "https://idp.example.com/tenant/jwks"
CLIENT_ID = "client-123"


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class FakeTransport:
    def __init__(
        self,
        responses: Mapping[str, list[Mapping[str, object]]],
    ) -> None:
        self._responses = {
            url: [dict(item) for item in values]
            for url, values in responses.items()
        }
        self.calls: dict[str, int] = {}

    def get_json(self, url: str) -> Mapping[str, object]:
        self.calls[url] = self.calls.get(url, 0) + 1
        responses = self._responses.get(url)
        if not responses:
            raise AssertionError(f"Unexpected URL: {url}")
        if len(responses) > 1:
            return responses.pop(0)
        return responses[0]


def _metadata(
    *,
    issuer: str = ISSUER,
    jwks_uri: str = JWKS_URI,
    algorithms: list[str] | None = None,
) -> dict[str, object]:
    return {
        "issuer": issuer,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": jwks_uri,
        "userinfo_endpoint": ISSUER + "/userinfo",
        "id_token_signing_alg_values_supported": algorithms or ["RS256"],
    }


def _b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    encoded = value.to_bytes(size, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _rsa_pair(key_id: str) -> tuple[rsa.RSAPrivateKey, dict[str, object]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    public_jwk: dict[str, object] = {
        "kty": "RSA",
        "kid": key_id,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    return private_key, public_jwk


def _id_token(
    private_key: rsa.RSAPrivateKey,
    *,
    key_id: str,
    subject: str = "subject-42",
) -> str:
    return pyjwt.encode(
        {
            "iss": ISSUER,
            "sub": subject,
            "aud": CLIENT_ID,
            "exp": int((NOW + timedelta(minutes=10)).timestamp()),
            "iat": int(NOW.timestamp()),
            "auth_time": int((NOW - timedelta(minutes=1)).timestamp()),
            "nonce": "nonce-123",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": key_id, "typ": "JWT"},
    )


def test_discovery_uses_path_issuer_url_and_caches_metadata() -> None:
    clock = FrozenClock(NOW)
    transport = FakeTransport({DISCOVERY_URL: [_metadata()]})
    discovery = OidcDiscoveryClient(
        transport=transport,
        clock=clock,
        cache_ttl=timedelta(hours=1),
    )

    first = discovery.discover(ISSUER)
    second = discovery.discover(ISSUER)

    assert first == second
    assert first.issuer == ISSUER
    assert first.jwks_uri == JWKS_URI
    assert transport.calls[DISCOVERY_URL] == 1

    clock.value = NOW + timedelta(hours=1)
    discovery.discover(ISSUER)
    assert transport.calls[DISCOVERY_URL] == 2


def test_discovery_rejects_metadata_issuer_mismatch() -> None:
    transport = FakeTransport(
        {
            DISCOVERY_URL: [
                _metadata(issuer="https://other.example.com"),
            ]
        }
    )
    discovery = OidcDiscoveryClient(
        transport=transport,
        clock=FrozenClock(NOW),
    )

    with pytest.raises(OidcDiscoveryError, match="exactly match"):
        discovery.discover(ISSUER)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_endpoint", "http://idp.example.com/authorize"),
        ("token_endpoint", "https://idp.example.com/token#fragment"),
        ("jwks_uri", "http://idp.example.com/jwks"),
    ],
)
def test_discovery_rejects_unsafe_endpoints(field: str, value: str) -> None:
    metadata = _metadata()
    metadata[field] = value
    transport = FakeTransport({DISCOVERY_URL: [metadata]})

    with pytest.raises(OidcDiscoveryError):
        OidcDiscoveryClient(
            transport=transport,
            clock=FrozenClock(NOW),
        ).discover(ISSUER)


def test_discovered_verifier_validates_real_rsa_id_token_and_caches_remote_state() -> None:
    private_key, public_jwk = _rsa_pair("key-1")
    transport = FakeTransport(
        {
            DISCOVERY_URL: [_metadata()],
            JWKS_URI: [{"keys": [public_jwk]}],
        }
    )
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="provider-1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        algorithm="RS256",
        transport=transport,
        clock=FrozenClock(NOW),
        leeway=timedelta(0),
    )
    token = _id_token(private_key, key_id="key-1")

    first = verifier.verify_identity_token(token, expected_nonce="nonce-123")
    second = verifier.verify_identity_token(token, expected_nonce="nonce-123")

    assert first == second
    assert first.provider_id == "provider-1"
    assert first.subject == "subject-42"
    assert transport.calls[DISCOVERY_URL] == 1
    assert transport.calls[JWKS_URI] == 1


def test_unknown_kid_refreshes_after_cooldown_and_supports_key_rotation() -> None:
    clock = FrozenClock(NOW)
    old_private, old_jwk = _rsa_pair("old")
    new_private, new_jwk = _rsa_pair("new")
    transport = FakeTransport(
        {
            DISCOVERY_URL: [_metadata()],
            JWKS_URI: [
                {"keys": [old_jwk]},
                {"keys": [old_jwk, new_jwk]},
            ],
        }
    )
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="provider-1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        algorithm="RS256",
        transport=transport,
        clock=clock,
        unknown_kid_refresh_cooldown=timedelta(seconds=30),
        leeway=timedelta(0),
    )

    verifier.verify_identity_token(
        _id_token(old_private, key_id="old"),
        expected_nonce="nonce-123",
    )
    clock.value = NOW + timedelta(seconds=31)
    rotated = verifier.verify_identity_token(
        _id_token(new_private, key_id="new"),
        expected_nonce="nonce-123",
    )

    assert rotated.subject == "subject-42"
    assert transport.calls[JWKS_URI] == 2


def test_unknown_kid_does_not_cause_repeated_refresh_inside_cooldown() -> None:
    clock = FrozenClock(NOW)
    old_private, old_jwk = _rsa_pair("old")
    unknown_private, _ = _rsa_pair("unknown")
    transport = FakeTransport(
        {
            DISCOVERY_URL: [_metadata()],
            JWKS_URI: [{"keys": [old_jwk]}],
        }
    )
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="provider-1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        algorithm="RS256",
        transport=transport,
        clock=clock,
        unknown_kid_refresh_cooldown=timedelta(seconds=30),
        leeway=timedelta(0),
    )
    verifier.verify_identity_token(
        _id_token(old_private, key_id="old"),
        expected_nonce="nonce-123",
    )
    unknown = _id_token(unknown_private, key_id="unknown")

    for _ in range(2):
        with pytest.raises(InvalidIdentityToken, match="unknown"):
            verifier.verify_identity_token(unknown, expected_nonce="nonce-123")

    assert transport.calls[JWKS_URI] == 1


@pytest.mark.parametrize(
    "jwk",
    [
        {
            "kty": "oct",
            "kid": "secret",
            "use": "sig",
            "alg": "RS256",
            "k": "c2VjcmV0",
        },
        {
            "kty": "RSA",
            "kid": "private",
            "use": "sig",
            "alg": "RS256",
            "n": "AQAB",
            "e": "AQAB",
            "d": "private",
        },
    ],
)
def test_jwks_rejects_symmetric_or_private_key_material(jwk: dict[str, object]) -> None:
    transport = FakeTransport({JWKS_URI: [{"keys": [jwk]}]})
    resolver = JwksKeyResolver(
        jwks_uri=JWKS_URI,
        transport=transport,
        clock=FrozenClock(NOW),
        algorithm="RS256",
    )

    with pytest.raises(OidcJwksError, match=r"symmetric|private"):
        resolver.resolve(str(jwk["kid"]))


def test_jwks_skips_non_signing_or_wrong_algorithm_keys() -> None:
    _, enc_jwk = _rsa_pair("enc")
    _, wrong_alg_jwk = _rsa_pair("wrong")
    enc_jwk["use"] = "enc"
    wrong_alg_jwk["alg"] = "RS512"
    transport = FakeTransport(
        {
            JWKS_URI: [
                {
                    "keys": [enc_jwk, wrong_alg_jwk],
                }
            ]
        }
    )
    resolver = JwksKeyResolver(
        jwks_uri=JWKS_URI,
        transport=transport,
        clock=FrozenClock(NOW),
        algorithm="RS256",
    )

    with pytest.raises(OidcJwksError, match="usable"):
        resolver.resolve("missing")


def test_discovered_verifier_rejects_unadvertised_algorithm_before_jwks_fetch() -> None:
    private_key, _ = _rsa_pair("key-1")
    transport = FakeTransport(
        {
            DISCOVERY_URL: [_metadata(algorithms=["RS512"])],
            JWKS_URI: [{"keys": []}],
        }
    )
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="provider-1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        algorithm="RS256",
        transport=transport,
        clock=FrozenClock(NOW),
    )

    with pytest.raises(OidcConfigurationError, match="not advertised"):
        verifier.verify_identity_token(_id_token(private_key, key_id="key-1"))

    assert JWKS_URI not in transport.calls


def test_discovered_verifier_requires_kid_before_jwks_fetch() -> None:
    private_key, _ = _rsa_pair("unused")
    token = pyjwt.encode(
        {
            "iss": ISSUER,
            "sub": "subject-42",
            "aud": CLIENT_ID,
            "exp": int((NOW + timedelta(minutes=10)).timestamp()),
            "iat": int(NOW.timestamp()),
        },
        private_key,
        algorithm="RS256",
    )
    transport = FakeTransport(
        {
            DISCOVERY_URL: [_metadata()],
            JWKS_URI: [{"keys": []}],
        }
    )
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="provider-1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        algorithm="RS256",
        transport=transport,
        clock=FrozenClock(NOW),
    )

    with pytest.raises(InvalidIdentityToken, match="kid"):
        verifier.verify_identity_token(token)

    assert JWKS_URI not in transport.calls


def test_httpx_transport_accepts_json_and_jwk_set_media_types() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/metadata":
            return httpx.Response(
                200,
                json={"issuer": ISSUER},
                headers={"content-type": "application/json; charset=utf-8"},
            )
        return httpx.Response(
            200,
            json={"keys": []},
            headers={"content-type": "application/jwk-set+json"},
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxOidcTransport(client=client)

    assert transport.get_json("https://example.com/metadata")["issuer"] == ISSUER
    assert transport.get_json("https://example.com/jwks")["keys"] == []
    transport.close()
    client.close()


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"error": "boom"}),
        httpx.Response(
            200,
            text="not-json",
            headers={"content-type": "text/plain"},
        ),
    ],
)
def test_httpx_transport_rejects_http_or_media_type_errors(
    response: httpx.Response,
) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: response),
        follow_redirects=False,
    )
    transport = HttpxOidcTransport(client=client)

    with pytest.raises(OidcRemoteError):
        transport.get_json("https://example.com/data")

    client.close()


def test_httpx_transport_rejects_json_arrays_and_invalid_json() -> None:
    responses = [
        httpx.Response(
            200,
            json=["not", "object"],
            headers={"content-type": "application/json"},
        ),
        httpx.Response(
            200,
            content=b"{invalid",
            headers={"content-type": "application/json"},
        ),
    ]

    for response in responses:
        client = httpx.Client(
            transport=httpx.MockTransport(lambda _request, item=response: item),
            follow_redirects=False,
        )
        transport = HttpxOidcTransport(client=client)
        with pytest.raises(OidcRemoteError):
            transport.get_json("https://example.com/data")
        client.close()
