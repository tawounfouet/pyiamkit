# JWT Access Tokens — 0.3.0b1

## Purpose

`0.3.0b1` introduces signed JWT access tokens without turning JWT into the source of truth for Authentication or Authorization.

The design is intentionally session-aware:

```text
AuthenticationContext
        ↓
durable Session
        ↓
JwtTokenProvider.issue_access_token()
        ↓
signed access JWT
        ↓
JwtTokenProvider.verify_access_token()
        ├── cryptographic verification
        ├── issuer / audience / algorithm checks
        └── durable Session revalidation
                ↓
        AccessTokenClaims
```

A valid JWT signature is necessary but not sufficient.

## Security model

The adapter follows five core rules:

1. allowed algorithms come from trusted application configuration;
2. issuer and audience are mandatory configuration;
3. access-token lifetime cannot exceed Session lifetime;
4. verification reloads the referenced Session;
5. authorization state is not frozen into JWT Roles or Permissions.

This trades fully stateless verification for immediate Session revocation semantics.

## Core vs adapter

Framework-neutral contracts live in `pyiamkit.authentication`:

```text
TokenProvider
AccessTokenClaims
IssuedAccessToken
TokenId
TokenType
TokenError
TokenConfigurationError
InvalidAccessToken
ExpiredAccessToken
TokenSessionInactive
```

PyJWT-specific code lives only in:

```text
pyiamkit.authentication.adapters.jwt.JwtTokenProvider
```

The core package can still be imported without installing PyJWT.

## Installation

```bash
python -m pip install "pyiamkit[jwt]"
```

The extra currently targets PyJWT 2.x with its cryptographic algorithms extra.

## Token claims

The access JWT contains:

```text
iss         configured issuer
sub         PyIAMKit Identity ID
aud         configured audience(s)
exp         token expiration
iat         issuance time
jti         unique Token ID
sid         durable Session ID
auth_time   original authentication time
aal         Authentication assurance level
auth_method Authentication method
mfa         MFA state
amr         compact authentication-method list
token_use   "access"
```

The token deliberately excludes:

```text
roles
permissions
role bindings
policy results
SoD decisions
resource attributes
credential references
raw credentials
```

Authorization is evaluated against current server-side IAM state.

## Issuance

`issue_access_token(session)` requires an active Session at the injected Clock time.

Effective token expiration is:

```text
min(
    issued_at + configured_access_token_ttl,
    session.expires_at,
)
```

A token can therefore never outlive its Session.

The adapter uses second-precision NumericDate claims to match JWT semantics deterministically.

## Verification pipeline

```text
raw token
   ↓
parse JOSE header
   ↓
header.alg == configured algorithm?
   ├── no → DENY
   ↓ yes
select configured verification key
   ├── key set configured → require known kid
   ↓
verify signature
   ↓
verify configured issuer
   ↓
verify configured audience
   ↓
require registered/session claims
   ↓
parse PyIAMKit claims
   ↓
verify exp / iat with injected Clock
   ↓
load Session by sid
   ↓
Session exists and is active?
   ├── no → DENY
   ↓ yes
cross-check:
   sub == session.identity_id
   exp <= session.expires_at
   aal == session.context.assurance_level
   auth_method == session.context.method
   mfa == session.context.mfa
   auth_time == session.context.authenticated_at
   ↓
trusted AccessTokenClaims
```

## Algorithm-confusion defense

The allowed algorithm is never read from the token and then trusted.

The adapter first compares the untrusted header against the configured algorithm and then calls PyJWT with exactly:

```text
algorithms=[configured_algorithm]
```

The same configuration boundary owns the signing/verification key.

`none` and any algorithm outside the adapter allowlist are rejected during configuration.

## Issuer and audience

Issuer and at least one audience are mandatory.

Verification passes both trusted values to the JWT library. A token signed by the expected key but minted for another issuer or audience is rejected.

## Signing-key rotation

The adapter can be configured with:

```text
key_id="current-2026-09"
verification_keys={
    "previous-2026-08": old_public_key,
    "current-2026-09": current_public_key,
}
```

Issued tokens carry the configured `kid`.

When a verification-key mapping exists:

- `kid` is required;
- an unknown `kid` fails closed;
- the header cannot inject an arbitrary key or algorithm.

Key loading, HSM/KMS integration and automated JWKS publication remain adapter/infrastructure concerns.

## Revocation semantics

JWT revocation is derived from durable Session state.

Example:

```text
T0  Session ACTIVE
T1  access JWT issued
T2  JWT verifies
T3  Session REVOKED
T4  same JWT signature remains cryptographically valid
T5  verification reloads Session
T6  TokenSessionInactive
```

This gives immediate logout/security-reset semantics without maintaining a separate access-token blacklist.

## Authentication context integrity

JWT claims mirror selected Session authentication context:

- subject;
- assurance level;
- authentication method;
- MFA state;
- authentication time.

Verification cross-checks those values against the current Session. A correctly signed token whose Authentication claims no longer match the Session fails closed.

## No authorization snapshot

PyIAMKit deliberately does not put current Roles or Permissions into the access JWT as trusted authorization state.

Why:

```text
RoleBinding changed
Policy changed
SoD rule changed
Permission revoked
Tenant access revoked
        ↓
old JWT with embedded permissions would be stale
```

Instead, the host application uses verified Identity/Session context and calls the Authorization Engine against current IAM state.

## Refresh tokens

Refresh tokens are explicitly out of scope for `0.3.0b1`.

Secure refresh rotation needs durable state such as:

```text
token family
current refresh identifier/hash
rotation counter
consumed/revoked timestamps
reuse detection
family-wide compromise response
```

PyIAMKit does not claim refresh-token rotation until that state model exists.

## Key material

Signing and verification keys are constructor/configuration inputs.

This milestone does not persist:

- HMAC signing secrets;
- RSA/EC/EdDSA private keys;
- bearer tokens;
- refresh tokens.

Production applications should source signing material from an appropriate secret manager, KMS or HSM-backed adapter.

## Tests

The security suite covers:

- issue/verify round-trip;
- absence of Roles and Permissions from payload;
- Session-capped expiration;
- token expiration with injected Clock;
- post-issuance Session revocation;
- wrong issuer;
- wrong audience;
- tampered compact JWT;
- algorithm mismatch;
- unsafe `none` configuration;
- required/unknown `kid`;
- Session/claim consistency.

The standard CI still qualifies Python 3.12 and 3.13, mypy strict, Ruff, coverage, wheel installation, executable examples and Bandit.

## Next milestone

`0.3.0b2 — FastAPI integration` should consume these contracts rather than reimplement JWT semantics.

Expected adapter flow:

```text
Authorization header
        ↓
FastAPI dependency
        ↓
TokenProvider.verify_access_token()
        ↓
AccessTokenClaims
        ↓
tenant/scope resolution
        ↓
AuthorizationEngine
        ↓
endpoint execution or 401/403
```

HTTP concerns remain outside the Authentication core.
