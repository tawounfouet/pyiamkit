# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** SCIM Group provisioning beta (`0.4.0b7`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0b7` adds **SCIM Group provisioning** without turning external groups into authorization Roles.

```text
SCIM User resources
        ↓
ProvisioningUser
        ↓
member resource IDs
        ↓
ProvisioningGroup
        ↓
SCIM /Groups transport
```

When Group provisioning is configured, PyIAMKit exposes:

```text
POST   /Groups
GET    /Groups
GET    /Groups/{id}
PUT    /Groups/{id}
PATCH  /Groups/{id}
DELETE /Groups/{id}
```

Group discovery is then added to `/ResourceTypes` and `/Schemas`. The FastAPI router adds `/Groups` only when a Group service is explicitly configured.

Every Group member must reference an active SCIM User resource managed by the same provisioning source and Tenant. Group DELETE tombstones the Group but preserves its Users, Identities and Tenant Memberships.

Supported Group filters are:

```text
displayName eq "..."
externalId eq "..."
```

Generic SCIM, Microsoft Entra and Okta profiles are now Group-capable. Nested Groups are intentionally disabled in this milestone.

A SCIM Group does **not** become a PyIAMKit Role, does not grant Permissions and does not create RoleBindings. Any future external Group → Role feature must use an explicit mapping policy rather than name equality.

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

TOTP MFA:

```bash
python -m pip install -e ".[mfa]"
```

FastAPI integration:

```bash
python -m pip install -e ".[fastapi]"
```

Django integration:

```bash
python -m pip install -e ".[django]"
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

## SCIM Group guarantees in 0.4.0b7

- Group resources are source- and Tenant-scoped;
- member IDs must resolve to active managed `ProvisioningUser` resources;
- Group membership has no implicit RBAC meaning;
- Group names never map to Role names automatically;
- nested Groups are unsupported in this milestone;
- Group PUT/PATCH/DELETE support ETag / `If-Match`;
- member add/remove operations are idempotent;
- Group DELETE preserves Users, Identities and Tenant Memberships;
- SQLAlchemy/PostgreSQL persist Group membership independently from authorization tables;
- Group HTTP routes remain protected by the host-provided SCIM access dependency;
- password provisioning remains rejected.

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
0.4.0b1    MFA enrollment / TOTP step-up
0.4.0b2    Assurance-aware authorization / step-up requirements
0.4.0b3    Django integration
0.4.0b4    SCIM User provisioning core
0.4.0b5    SCIM HTTP transport + FastAPI router
0.4.0b6    SCIM provider interoperability profiles
0.4.0b7    SCIM Group provisioning + HTTP transport
0.4.x      Provider qualification / explicit Group mapping policy
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
