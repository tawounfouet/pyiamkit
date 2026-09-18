import base64
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from pyiamkit.authentication.adapters.oidc_discovery import (
    DiscoveredOidcIdTokenVerifier,
)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class MemoryTransport:
    def __init__(self, responses: Mapping[str, Mapping[str, object]]) -> None:
        self.responses = {url: dict(payload) for url, payload in responses.items()}
        self.calls: dict[str, int] = {}

    def get_json(self, url: str) -> Mapping[str, object]:
        self.calls[url] = self.calls.get(url, 0) + 1
        return self.responses[url]


def b64url_uint(value: int) -> str:
    size = max(1, (value.bit_length() + 7) // 8)
    encoded = value.to_bytes(size, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)
issuer = "https://idp.example.com/tenant"
discovery_url = issuer + "/.well-known/openid-configuration"
jwks_uri = issuer + "/jwks"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
numbers = private_key.public_key().public_numbers()
public_jwk: dict[str, object] = {
    "kty": "RSA",
    "kid": "signing-key-1",
    "use": "sig",
    "alg": "RS256",
    "n": b64url_uint(numbers.n),
    "e": b64url_uint(numbers.e),
}

transport = MemoryTransport(
    {
        discovery_url: {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/authorize",
            "token_endpoint": issuer + "/token",
            "jwks_uri": jwks_uri,
            "id_token_signing_alg_values_supported": ["RS256"],
        },
        jwks_uri: {"keys": [public_jwk]},
    }
)

verifier = DiscoveredOidcIdTokenVerifier(
    provider_id="example-oidc",
    issuer=issuer,
    client_id="pyiamkit-client",
    algorithm="RS256",
    transport=transport,
    clock=clock,
    leeway=timedelta(0),
)

id_token = pyjwt.encode(
    {
        "iss": issuer,
        "sub": "external-subject-42",
        "aud": "pyiamkit-client",
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "iat": int(now.timestamp()),
        "nonce": "nonce-123",
    },
    private_key,
    algorithm="RS256",
    headers={"kid": "signing-key-1"},
)

claims = verifier.verify_identity_token(
    id_token,
    expected_nonce="nonce-123",
)
verifier.verify_identity_token(
    id_token,
    expected_nonce="nonce-123",
)

assert claims.subject == "external-subject-42"
assert transport.calls[discovery_url] == 1
assert transport.calls[jwks_uri] == 1

print(
    "OIDC Discovery/JWKS OK:",
    claims.subject,
    transport.calls[discovery_url],
    transport.calls[jwks_uri],
)
