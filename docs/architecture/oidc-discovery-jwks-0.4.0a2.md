# OIDC Discovery & JWKS — 0.4.0a2

## Purpose

`0.4.0a2` adds provider metadata discovery and remote public-key rotation to
the OIDC federation model introduced in `0.4.0a1`.

The trust chain remains explicit:

```text
trusted configured issuer
        ↓
OIDC Discovery
        ↓
validated provider metadata
        ↓
HTTPS jwks_uri
        ↓
cached public signing keys
        ↓
kid resolution
        ↓
existing static OIDC verifier
        ↓
FederatedIdentityClaims
```

Discovery does not create a new identity model and does not change local
authorization semantics.

## Package boundary

The network-dependent implementation lives in:

```text
pyiamkit.authentication.adapters.oidc_discovery
```

The Authentication core remains free from HTTPX and remote-network concerns.

Install:

```bash
python -m pip install "pyiamkit[oidc-http]"
```

The extra includes PyJWT cryptographic support and HTTPX.

## Components

```text
OidcJsonTransport
├── HttpxOidcTransport
│
OidcDiscoveryClient
├── OidcProviderMetadata
│
JwksKeyResolver
│
└── DiscoveredOidcIdTokenVerifier
        ↓
    StaticOidcIdTokenVerifier
```

## Trust anchor

The configured issuer is the trust anchor.

The verifier never discovers an issuer from an incoming token.

```text
application config
issuer = https://idp.example.com/tenant
        ↓
discovery URL
https://idp.example.com/tenant/.well-known/openid-configuration
```

The returned metadata must contain exactly:

```text
issuer == configured issuer
```

A mismatch fails closed.

## Discovery metadata

Required fields in this milestone:

```text
issuer
authorization_endpoint
token_endpoint
jwks_uri
id_token_signing_alg_values_supported
```

Optional:

```text
userinfo_endpoint
```

The milestone targets Authorization Code style clients, so the token endpoint is
required even though some narrower OpenID Provider modes may not need it.

## Endpoint validation

The following must be HTTPS:

- issuer;
- authorization endpoint;
- token endpoint;
- JWKS endpoint;
- optional UserInfo endpoint.

Fragments are rejected.

The issuer itself may not contain a query string.

Authorization/token/JWKS endpoints may contain provider-defined query
components where required.

The reference HTTP transport does not follow redirects by default.

## Metadata cache

`OidcDiscoveryClient` caches validated metadata per configured issuer.

Default TTL:

```text
1 hour
```

Cache behavior uses the injected `Clock`.

```text
discover()
   ↓
cache valid?
├── yes → return metadata
└── no  → GET discovery document
           ↓
        validate
           ↓
        replace cache
```

Invalid remote data is never cached as trusted metadata.

## Transport abstraction

`OidcJsonTransport` is deliberately small:

```python
class OidcJsonTransport(Protocol):
    def get_json(self, url: str) -> Mapping[str, object]: ...
```

This allows applications to replace HTTPX with:

- enterprise proxy clients;
- service-mesh-aware clients;
- outbound allow-listed transports;
- test/memory transports.

## HTTPX reference adapter

`HttpxOidcTransport` provides:

- synchronous GET;
- default five-second timeout;
- redirects disabled when it owns the client;
- JSON media-type validation;
- JSON-object validation;
- HTTP error normalization.

Accepted media types:

```text
application/json
application/jwk-set+json
```

The caller can inject and own an existing `httpx.Client`.

## JWKS trust model

Remote JWKS is treated as untrusted input until each key is validated.

The resolver rejects:

```text
kty = oct
k
d
p
q
dp
dq
qi
oth
```

This prevents remote symmetric or private key material from becoming part of
the reference verification set.

The resolver retains only keys that:

- have a non-empty `kid`;
- are signing keys when `use` is present;
- match the configured algorithm when `alg` is present;
- can be parsed by PyJWT as a public JWK.

If no usable key remains, resolution fails closed.

## Configured algorithm

The application still chooses one verification algorithm.

```text
configured algorithm
        ↓
must be advertised in Discovery metadata
        ↓
must match ID Token JOSE header
        ↓
must match JWK alg when JWK alg is present
```

Provider metadata does not automatically expand the application's algorithm
allowlist.

## JWKS cache

Default JWKS TTL:

```text
5 minutes
```

The resolver maintains:

```text
kid -> PyJWK
expires_at
last_refresh_at
```

A cache expiration performs a normal refresh.

## Unknown-kid rotation

A new provider signing key typically appears as a new `kid`.

Resolver behavior:

```text
token kid
   ↓
cache lookup
   ↓
known?
├── yes → use cached key
└── no
    ↓
cooldown elapsed since last JWKS refresh?
├── no  → fail unknown kid
└── yes → refresh JWKS once
           ↓
        retry kid
           ↓
        known? yes → verify
               no  → fail
```

Default unknown-key refresh cooldown:

```text
30 seconds
```

This balances key rotation against attacker-controlled refresh amplification.

## Concurrency

Discovery and JWKS cache mutation use re-entrant locks.

The objective is to avoid concurrent refresh storms inside a process.

The locks are local-process coordination only; distributed cache coordination
is not part of this milestone.

## Discovered verifier

`DiscoveredOidcIdTokenVerifier` orchestrates infrastructure but does not
duplicate claim semantics.

Flow:

```text
discover issuer metadata
        ↓
verify configured algorithm advertised
        ↓
parse unverified JOSE header only for alg/kid routing
        ↓
resolve public JWK
        ↓
construct StaticOidcIdTokenVerifier
        ↓
verify signature + issuer + audience + nonce + azp + time
```

The existing static verifier remains authoritative for ID Token claim
validation.

## Metadata changes

The discovered verifier recreates its JWKS resolver if the validated
`jwks_uri` changes after metadata cache expiry.

This allows controlled provider metadata evolution while preserving exact
issuer trust.

## SSRF / outbound networking boundary

The framework does not derive issuer URLs from arbitrary request data.

The issuer is application configuration.

Applications with strict egress requirements should provide an
`OidcJsonTransport` that enforces their own:

- DNS/IP allowlists;
- proxy route;
- certificate policy;
- network namespace;
- private-address restrictions.

PyIAMKit validates protocol shape but does not pretend to know every host
application's network policy.

## Failure taxonomy

```text
OidcDiscoveryError
  invalid provider metadata / URL shape

OidcRemoteError
  remote HTTP / JSON transport failure

OidcJwksError
  invalid or unsafe JWKS

InvalidIdentityToken
  token header, kid or cryptographic/claim failure

OidcConfigurationError
  unsafe local verifier configuration
```

Failures are explicit and fail closed.

## Tests

The milestone qualifies:

- issuer-with-path discovery URL;
- exact discovered issuer match;
- unsafe endpoint rejection;
- metadata cache behavior;
- real RSA ID Token verification;
- JWKS cache reuse;
- signing-key rotation;
- unknown-kid cooldown;
- symmetric-key rejection;
- private-key-material rejection;
- non-signing/wrong-algorithm key filtering;
- unadvertised configured algorithm;
- missing token `kid`;
- HTTP JSON/JWK media types;
- HTTP status, invalid media type and malformed JSON failures.

The standard Python 3.12/3.13, mypy strict, coverage, PostgreSQL, build, smoke,
examples and Bandit gates remain mandatory.

## Non-goals

`0.4.0a2` does not implement:

- automatic Identity provisioning;
- dynamic client registration;
- OAuth2 authorization requests;
- PKCE state persistence;
- logout protocols;
- UserInfo synchronization;
- distributed JWKS caches;
- vendor-specific Entra/Okta/Auth0/Keycloak policy;
- certificate pinning;
- application-specific egress allowlists.

These remain later adapters or host-application responsibilities.

## Next milestone

`0.4.0b1` can now focus on MFA enrollment and step-up semantics while OIDC
federation already has a production-shaped provider key-discovery boundary.
