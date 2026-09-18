# OIDC Federation — 0.4.0a1

## Purpose

`0.4.0a1` introduces PyIAMKit's first external authentication federation path.

The milestone validates an OpenID Connect ID Token, resolves the external subject to an already linked internal Identity and opens a local PyIAMKit Session.

```text
OIDC Provider
    ↓
ID Token
    ↓
IdentityTokenVerifier
    ↓
FederatedIdentityClaims
    ↓
(provider_id, subject)
    ↓
IdentityRepository
    ↓
internal Identity
    ↓
FederatedAssuranceResolver
    ↓
AuthenticationApplicationService
    ↓
local OIDC Session
```

The external provider proves identity. PyIAMKit remains authoritative for local Identity lifecycle, tenancy, RoleBindings, Permissions, policies, constraints and SoD.

## Identity key

Federated identity resolution uses:

```text
(provider_id, external_subject)
```

For OIDC:

```text
external_subject = verified sub claim
```

Email is not an identity key.

This means:

```text
same verified email
different OIDC sub
        ↓
NO automatic account linking
```

Explicit account-linking workflows remain separate administrative/user-consent operations.

## Framework-neutral contracts

The Authentication core exposes:

```text
FederatedIdentityClaims
FederatedAssurance
IdentityTokenVerifier
FederatedAssuranceResolver
FederatedAuthenticationService
FederationError
InvalidIdentityToken
ExternalIdentityNotLinked
InvalidFederationPolicy
```

None of these contracts import PyJWT, HTTP clients, FastAPI, Django or a vendor SDK.

## OIDC adapter

The optional adapter lives at:

```text
pyiamkit.authentication.adapters.oidc
```

and provides:

```text
StaticOidcIdTokenVerifier
StaticOidcAssuranceResolver
OidcConfigurationError
```

Install with:

```bash
python -m pip install "pyiamkit[oidc]"
```

## ID Token validation

The static verifier is configured with:

```text
provider_id
issuer
client_id
verification_key OR verification_keys[kid]
algorithm
Clock
leeway
```

Validation pipeline:

```text
compact ID Token
       ↓
read JOSE header
       ↓
header.alg == configured algorithm?
       ├── no → DENY
       ↓ yes
select verification key
       ├── key set configured → require known kid
       ↓
verify JWS signature
       ↓
iss == configured issuer
       ↓
aud contains configured client_id
       ↓
require iss/sub/aud/exp/iat
       ↓
validate exp and iat with injected Clock
       ↓
expected nonce?
       ├── yes → require exact nonce
       ↓
multiple audiences?
       ├── yes → require azp == client_id
       ↓
verified FederatedIdentityClaims
```

The signing algorithm comes from trusted configuration. It is not selected by the untrusted token.

## Issuer configuration

The configured issuer must be:

- HTTPS;
- non-empty;
- have a network location;
- contain no query;
- contain no fragment.

Token verification then requires exact issuer equality.

## Subject constraints

The OIDC subject:

- is required;
- is case-sensitive;
- must be non-empty;
- must be ASCII;
- must not exceed 255 bytes.

PyIAMKit stores and resolves it exactly as the external subject value.

## Audience and authorized party

The configured client ID must be a token audience.

For one audience:

```text
aud = client_id
```

If `azp` is present it must equal the configured client ID.

For multiple audiences:

```text
aud = [client_id, ...]
azp = client_id  # required by the adapter
```

Missing or mismatched `azp` fails closed.

## Nonce

If the calling authorization flow supplies an expected nonce, the verified ID Token must contain exactly the same nonce.

```text
authorization request nonce
          ↓
expected_nonce
          ↓
ID Token nonce
          ↓
constant-time equality check
```

If the caller did not use nonce, the verifier does not invent one.

Replay-state storage remains a host/client concern in this static verifier milestone.

## Temporal claims

Required:

```text
iat
exp
```

Optional:

```text
auth_time
```

The injected Clock enables deterministic verification.

The verifier rejects:

- expired ID Tokens;
- tokens issued too far in the future;
- future `auth_time`;
- invalid NumericDate values.

Configured leeway is explicit.

## Verified external claims

`FederatedIdentityClaims` can carry:

```text
provider_id
issuer
subject
audiences
issued_at
expires_at
auth_time?
nonce?
authorized_party?
acr?
amr[]
email?
email_verified?
```

These are authentication facts, not local authorization assignments.

## Assurance mapping

OIDC `acr` and `amr` values are provider-specific.

PyIAMKit therefore does not globally assume:

```text
acr X == AAL2
amr Y == MFA
```

Instead:

```python
StaticOidcAssuranceResolver(
    acr_mapping={
        "urn:example:aal2": AssuranceLevel.AAL2,
    },
    mfa_amr_values=("mfa", "otp"),
)
```

Unknown ACR values fall back to the configured default, which is AAL1.

MFA is false unless at least one explicitly configured AMR value matches.

## Local federation service

`FederatedAuthenticationService.authenticate()` performs:

```text
verify ID Token
       ↓
find_by_external_subject(provider_id, subject)
       ↓
Identity found?
  no → ExternalIdentityNotLinked
       ↓ yes
resolve local assurance
       ↓
AuthenticationApplicationService.open_session()
       ↓
active Identity check
       ↓
OIDC Session
```

The local Session uses:

```text
method = OIDC
provider_id = external provider ID
authenticated_at = auth_time or iat
assurance_level = explicit resolver result
mfa = explicit resolver result
```

The Session lifetime is a local PyIAMKit policy and is not derived automatically from email or authorization claims.

## Local authorization remains authoritative

OIDC claims do not create:

- Tenant Memberships;
- Roles;
- RoleBindings;
- Permissions;
- policy ALLOW decisions;
- SoD exemptions.

External groups/roles can be integrated later only through explicit mapping/provisioning policy.

## No automatic provisioning

An unknown external subject fails with:

```text
ExternalIdentityNotLinked
```

This milestone does not auto-create an internal Identity from ID Token claims.

That is deliberate because provisioning requires separate decisions about:

- identity lifecycle ownership;
- tenant membership;
- consent;
- source authority;
- deprovisioning;
- duplicate-account handling;
- audit;
- account recovery.

## Static keys in 0.4.0a1

The initial verifier accepts explicitly configured verification keys.

Two modes:

```text
single verification_key
```

or:

```text
verification_keys = {
    "kid-1": public_key_1,
    "kid-2": public_key_2,
}
```

When a key mapping is configured, the token must contain a known `kid`.

OIDC Discovery and remote JWKS refresh are intentionally deferred to `0.4.0a2`.

## Security boundaries

```text
External IdP
   │ trusted only after token verification
   ▼
FederatedIdentityClaims
   │ authentication evidence only
   ▼
Identity link
   │ local identity boundary
   ▼
Session
   │ local authentication state
   ▼
AuthorizationEngine
   │ local authorization truth
   ▼
business action
```

A provider compromise or mapping error must not implicitly become a global authorization bypass.

## Tests

The milestone qualifies:

- valid ID Token verification;
- issuer mismatch;
- audience mismatch;
- nonce missing/mismatch;
- multi-audience `azp`;
- expiration;
- future issuance;
- fixed-algorithm defense;
- missing/unknown `kid`;
- configured ACR/AMR mapping;
- OIDC subject constraints;
- exact provider+subject Identity resolution;
- no email auto-linking;
- inactive local Identity denial;
- local OIDC Session creation.

Existing Python 3.12/3.13, coverage, PostgreSQL, build, smoke, examples and Bandit gates remain mandatory.

## Next milestone

`0.4.0a2` should add provider infrastructure:

```text
OIDC Discovery
    ↓
issuer metadata validation
    ↓
JWKS retrieval / caching / refresh
    ↓
key rotation
    ↓
StaticOidcIdTokenVerifier-compatible verification boundary
```

Vendor-specific Entra ID, Keycloak, Auth0 or Okta configuration can then be implemented without changing the federation core.
