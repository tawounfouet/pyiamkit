# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** OIDC Discovery/JWKS alpha (`0.4.0a2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0a2` adds **OIDC Discovery and remote JWKS rotation** on top of the
federation core introduced in `0.4.0a1`.

```text
configured issuer
      ↓
OidcDiscoveryClient
      ↓
.well-known/openid-configuration
      ├── exact issuer match
      ├── HTTPS endpoints
      ├── jwks_uri
      └── advertised ID Token algorithms
      ↓
JwksKeyResolver
      ├── public signing keys only
      ├── TTL cache
      ├── kid lookup
      └── bounded refresh on unknown kid
      ↓
DiscoveredOidcIdTokenVerifier
      ↓
StaticOidcIdTokenVerifier
      ↓
FederatedIdentityClaims
```

The configured signing algorithm still comes from trusted application
configuration. Discovery only confirms that the provider advertises it; neither
metadata nor the ID Token header can silently change the verification
algorithm.

```python
from pyiamkit.authentication.adapters.oidc_discovery import (
    DiscoveredOidcIdTokenVerifier,
    HttpxOidcTransport,
)

with HttpxOidcTransport() as transport:
    verifier = DiscoveredOidcIdTokenVerifier(
        provider_id="entra-prod",
        issuer="https://login.example.com/tenant/v2.0",
        client_id="pyiamkit-client",
        algorithm="RS256",
        transport=transport,
        clock=clock,
    )
```

Discovery metadata and JWKS are cached separately. A new `kid` can trigger a
controlled JWKS refresh after a cooldown, reducing attacker-driven network
amplification while still supporting key rotation.

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

OIDC federation adapter with configured keys:

```bash
python -m pip install -e ".[oidc]"
```

OIDC Discovery + remote JWKS:

```bash
python -m pip install -e ".[oidc-http]"
```

FastAPI integration:

```bash
python -m pip install -e ".[fastapi]"
```

FastAPI + JWT:

```bash
python -m pip install -e ".[jwt,fastapi]"
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

## OIDC Discovery/JWKS guarantees in 0.4.0a2

- configured issuer remains the trust anchor;
- discovered issuer must match it exactly;
- remote OIDC endpoints must use HTTPS;
- provider metadata must advertise the configured ID Token algorithm;
- JWKS accepts public signing keys only;
- symmetric and private key material is rejected;
- `kid` is mandatory for discovered-key verification;
- metadata and JWKS have independent TTL caches;
- unknown-key refresh is rate-limited by a configurable cooldown;
- token claims continue to be validated by the existing OIDC verifier;
- network transport stays outside the Authentication core.

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
0.4.0a1    OIDC federation core + static-key ID Token verification
0.4.0a2    OIDC Discovery / JWKS cache and rotation
0.4.0b1    MFA enrollment / step-up
0.4.x      Django, SCIM and provider integrations
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
