# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** JWT beta (`0.3.0b1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.3.0b1` adds **JWT access tokens** as an optional adapter over the Session model introduced in `0.3.0a2`.

```text
Identity
   ↓
AuthenticationContext
   ↓
durable Session  ← source of truth for revocation / expiry / assurance
   ↓
JwtTokenProvider
   ↓
signed access JWT
   ↓
verify signature + issuer + audience + algorithm
   ↓
reload Session and cross-check authentication state
   ↓
trusted AccessTokenClaims
```

JWT does not replace server-side authentication state. A token with a valid signature is still rejected when its referenced Session is revoked, expired or missing.

The JWT payload is intentionally small:

```text
iss        issuer
sub        Identity ID
aud        audience
exp / iat  token lifetime
jti        token ID
sid        Session ID
auth_time  authentication time
aal        assurance level
auth_method
mfa
amr
token_use=access
```

Roles and Permissions are **not** embedded as an authorization source of truth. The Authorization Engine continues to resolve current RoleBindings, hierarchy, constraints and SoD rules.

```python
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider

tokens = JwtTokenProvider(
    issuer="https://iam.example.com",
    audience="api://billing",
    signing_key=signing_key,
    session_repository=sessions,
    clock=clock,
    algorithm="RS256",
)

issued = tokens.issue_access_token(session)
claims = tokens.verify_access_token(issued.token)
```

The allowed algorithm, issuer and audience come from trusted configuration. They are never selected from the untrusted token header. Optional `kid` lookup supports signing-key rotation.

`0.3.0b1` intentionally implements **access tokens only**. Refresh-token rotation and reuse detection require durable token-family state and are not simulated in this milestone.

## Installation

Python 3.12+ is required.

Core only:

```bash
python -m pip install -e .
```

SQLAlchemy persistence with SQLite or another SQLAlchemy-supported backend:

```bash
python -m pip install -e ".[sqlalchemy]"
```

PostgreSQL persistence with psycopg:

```bash
python -m pip install -e ".[postgres]"
```

JWT access-token adapter:

```bash
python -m pip install -e ".[jwt]"
```

Development checks:

```bash
python -m pip install build mypy pytest pytest-cov ruff
make check
```

See executable examples under `examples/` and architecture notes under `docs/architecture/`.

## Architecture

```text
Identity
   │
   ├── CredentialRepository
   │      └── Credential
   │          ├── opaque secret reference
   │          ├── type / fingerprint
   │          └── validity / revocation
   │
   └── SessionRepository
          └── Session
              ├── AuthenticationContext
              │    ├── method
              │    ├── assurance level
              │    ├── MFA state
              │    └── provider/device/network
              ├── expiration
              └── revocation

Authentication context
       ↓
AuthorizationRequest / host application context
       ↓
AuthorizationEngine
       ↓
AuthorizationDecision + Audit
```

The Authentication domain does not import SQLAlchemy, psycopg, JWT libraries, FastAPI, Django or an external IdP SDK. Persistence and future token/federation integrations depend inward on Authentication contracts.

## JWT guarantees in 0.3.0b1

- fixed configured JWT algorithm allowlist;
- mandatory issuer and audience validation;
- mandatory registered/token-link claims;
- access-token expiration capped by Session expiration;
- durable Session revalidation on every token verification;
- Session revocation invalidates already-issued access JWTs;
- subject, AAL, authentication method, MFA and `auth_time` cross-checked against Session state;
- optional `kid`-based verification key selection;
- unknown/missing `kid` fails closed when a key set is configured;
- no Roles or Permissions embedded as authorization truth;
- no refresh-token API in this milestone;
- signing/verification keys are configuration inputs and are not persisted by PyIAMKit.

## Roadmap

```text
0.0.1      Repository bootstrap
0.1.0a1    Identity domain
0.1.0a2    Tenancy / Membership
0.1.0b1    Roles & Permissions
0.1.0b2    RoleBindings + Scoped RBAC
0.2.0a1    Authorization Engine
0.2.0a2    Hierarchical RBAC
0.2.0b1    Constraints + Separation of Duties
0.2.0b2    Audit + decision explainability hardening
0.3.0a1    SQLAlchemy / SQLite / PostgreSQL persistence
0.3.0a2    Sessions + Credentials
0.3.0b1    JWT
0.3.0b2    FastAPI integration
0.4.x      Federation, MFA, Django, SCIM
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
