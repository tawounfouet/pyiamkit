# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** OIDC federation alpha (`0.4.0a1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0a1` adds the first **OIDC federation** path while preserving PyIAMKit's internal Identity and authorization boundaries.

```text
OIDC ID Token
     ↓
IdentityTokenVerifier
     ├── signature
     ├── issuer
     ├── audience / azp
     ├── exp / iat
     ├── nonce
     └── configured signing algorithm / kid
     ↓
FederatedIdentityClaims
     ↓
(provider_id, sub)
     ↓
IdentityRepository.find_by_external_subject()
     ↓
existing active PyIAMKit Identity
     ↓
explicit ACR / AMR assurance mapping
     ↓
AuthenticationApplicationService.open_session()
     ↓
local OIDC Session
```

The federation boundary deliberately does **not** use email as an identity key. Even a verified email claim cannot attach a new OIDC subject to an existing user. External Roles/groups/claims also do not create local RoleBindings or Permissions automatically.

The initial OIDC adapter uses configured verification keys and keeps network discovery/provider SDKs out of the core:

```python
from pyiamkit.authentication.adapters.oidc import (
    StaticOidcAssuranceResolver,
    StaticOidcIdTokenVerifier,
)

verifier = StaticOidcIdTokenVerifier(
    provider_id="entra-prod",
    issuer="https://login.example.com/tenant/v2.0",
    client_id="pyiamkit-client",
    verification_keys={"current": public_key},
    algorithm="RS256",
    clock=clock,
)

assurance = StaticOidcAssuranceResolver(
    acr_mapping={"urn:example:aal2": AssuranceLevel.AAL2},
    mfa_amr_values=("mfa",),
)
```

A separate `FederatedAuthenticationService` combines those adapters with the existing external identity links and Session lifecycle.

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

OIDC federation adapter:

```bash
python -m pip install -e ".[oidc]"
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

## OIDC federation guarantees in 0.4.0a1

- external identity keyed by provider ID plus OIDC subject;
- email never used for automatic identity linking;
- exact configured issuer and client audience validation;
- configured signing algorithm, never token-selected;
- nonce verification when an expected nonce is supplied;
- `azp` required for multiple audiences and validated when present;
- missing/unknown `kid` fails closed when a verification-key set is configured;
- local ACR/AMR assurance mapping is explicit and provider-specific;
- unknown ACR defaults to AAL1;
- MFA remains false unless configured AMR evidence matches;
- unlinked or inactive local Identities cannot establish Sessions;
- external authorization claims never bypass local RBAC, tenancy, policies or SoD.

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
0.4.0a2    External provider discovery / JWKS adapters
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
