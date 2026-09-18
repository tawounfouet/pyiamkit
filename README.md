# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** FastAPI integration beta (`0.3.0b2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.3.0b2` adds the first **FastAPI integration** without moving HTTP concerns into the IAM core.

```text
Authorization: Bearer <token>
        ↓
FastAPI HTTPBearer
        ↓
bearer_authentication()
        ↓
TokenProvider.verify_access_token()
        ↓
AccessTokenClaims
        ↓
require_permission()
        ├── host TenantResolver
        ├── optional ScopeResolver
        └── optional ResourceResolver
        ↓
AuthorizationEngine
        ↓
ALLOW → endpoint
DENY  → HTTP 403
```

Authentication and authorization remain distinct at the HTTP boundary:

```text
missing / invalid / revoked token → 401 + WWW-Authenticate: Bearer
valid identity but denied permission → 403
```

A minimal protected endpoint:

```python
from typing import Annotated

from fastapi import Depends
from pyiamkit.authorization import AuthorizationDecision, PermissionCode
from pyiamkit.integrations.fastapi import bearer_authentication, require_permission

authenticate = bearer_authentication(token_provider)

can_read_invoice = require_permission(
    authentication=authenticate,
    authorization_engine=authorization_engine,
    permission=PermissionCode("invoice.read"),
    tenant_resolver=resolve_tenant,
)


@app.get("/invoices")
def invoices(
    decision: Annotated[AuthorizationDecision, Depends(can_read_invoice)],
):
    return {"decision": str(decision.id)}
```

PyIAMKit deliberately does not guess the active tenant from an arbitrary request header. The host application supplies its Tenant resolver, and the Authorization Engine still validates active Tenant, Membership, scope, RoleBindings and governance.

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

## FastAPI guarantees in 0.3.0b2

- native HTTP Bearer/OpenAPI integration;
- token verification delegated to `TokenProvider`;
- generic 401 responses for missing/invalid authentication;
- `WWW-Authenticate: Bearer` on 401;
- permission evaluation delegated to `AuthorizationEngine`;
- authorization denial mapped to 403, not 401;
- Tenant resolution supplied explicitly by the host application;
- tenant-wide scope default, with custom Scope/Resource resolvers when required;
- existing Session revocation semantics preserved at the HTTP boundary;
- no FastAPI dependency in the core IAM packages.

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
