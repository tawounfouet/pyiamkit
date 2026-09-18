# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** SCIM HTTP transport beta (`0.4.0b5`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0b5` exposes the tenant-scoped provisioning core through a **SCIM 2.0 HTTP transport**.

```text
SCIM client
    ↓
explicit host access dependency
    ↓
FastAPI SCIM router
    ↓
ScimHttpTransport
    ↓
ScimProvisioningService
    ↓
Identity + tenant Membership + ProvisioningUser
```

Supported discovery and User endpoints:

```text
GET    /ServiceProviderConfig
GET    /ResourceTypes
GET    /ResourceTypes/User
GET    /Schemas
GET    /Schemas/{schema-uri}

POST   /Users
GET    /Users
GET    /Users/{id}
PUT    /Users/{id}
PATCH  /Users/{id}
DELETE /Users/{id}
```

SCIM responses use `application/scim+json`. Resource responses expose `Location` and `ETag`, and PUT/PATCH/DELETE forward `If-Match` to the provisioning core.

The initial filter capability is deliberately bounded to:

```text
userName eq "..."
externalId eq "..."
```

The FastAPI router requires an explicit application-provided access dependency. PyIAMKit does not expose anonymous provisioning routes by default and does not decide whether the host uses OAuth2 client credentials, mTLS, a gateway identity or another service-authentication mechanism.

SCIM Groups, full filter grammar, sorting, bulk operations and password provisioning remain outside this milestone.

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

## SCIM HTTP guarantees in 0.4.0b5

- `application/scim+json` is used for SCIM JSON responses;
- ServiceProviderConfig advertises only capabilities implemented by this release;
- User create returns HTTP 201 with resource representation, Location and ETag;
- stale `If-Match` conditions return HTTP 412;
- duplicate `userName` / `externalId` conflicts map to SCIM `uniqueness`;
- malformed or unsupported filters map to `invalidFilter`;
- unsupported PATCH paths map to `invalidPath`;
- internal Python exceptions are not exposed in SCIM 500 responses;
- the FastAPI router requires an explicit access dependency;
- password provisioning remains rejected;
- SCIM Groups cannot implicitly grant PyIAMKit Roles or Permissions;
- the existing tenant-scoped lifecycle semantics from `0.4.0b4` remain unchanged.

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
0.4.x      Provider interoperability profiles
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
