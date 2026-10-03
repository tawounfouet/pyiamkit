# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access
Management (IAM), RBAC, multi-tenancy, authorization, authentication, federation,
provisioning, auditability and durable persistence.

> **Status:** `1.0.0rc1` — public API freeze release candidate, built on the
> production-qualified 0.5.0 baseline. No new major IAM feature is introduced by
> this RC.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit Tenant/scope
boundaries, explainable authorization, strong revocation, auditable privileged
operations and framework-independent domain logic.

## Current milestone

`1.0.0rc1` freezes the public contract expected to become PyIAMKit 1.0.0.

```text
0.5.0 production-qualified capability surface
                    ↓
public API inventory
                    ↓
stable error / reason / permission review
                    ↓
adapter contract review
                    ↓
machine-readable compatibility manifest
                    ↓
1.0.0rc1 freeze
```

Four workflow families are release-blocking on the same commit:

```text
CI
Security
Production Qualification
API Compatibility
```

The API Compatibility gate freezes 27 documented namespaces and detects accidental
export, signature, enum, dataclass, exception-code and reviewed-constant drift.

Contract documentation:

- [Public API freeze](docs/api/public-api-freeze-1.0.0rc1.md)
- [1.x compatibility/deprecation policy](docs/api/compatibility-policy-1.0.md)
- [Error, reason-code and PermissionCode contracts](docs/api/error-reason-permission-contracts-1.0.md)
- [Adapter contract matrix](docs/api/adapter-contract-matrix-1.0.0rc1.md)
- [Production deployment](docs/guides/production-deployment.md)
- [Production checklist](docs/guides/production-checklist.md)

The next roadmap milestone is `1.0.0 — Stable Public API`.

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

Redis operational adapters:

```bash
python -m pip install -e ".[redis]"
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

## SCIM provider qualification guarantees in 0.4.0b8

- provider qualification exercises the public protected FastAPI SCIM path;
- Entra and Okta have separate visible CI gates;
- `excludedAttributes=members` is qualified for Entra Group reads;
- projection supports only implemented top-level attributes;
- `schemas`, `id` and `meta` remain always returned;
- Group membership remains independent from RBAC;
- no vendor SDK is required;
- no live provider secret is stored or used;
- qualification is not described as external certification;
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
0.4.0b8    SCIM provider offline qualification
0.4.x      Explicit Group mapping policy
0.5.0a1    Distributed cache, revocation, SecurityState and invalidation
0.5.0a2    Audit, transactional outbox, publisher and vendor-neutral SIEM export
0.5.0b1    Security hardening
0.5.0b2    Conformance suite
0.5.0rc1   Production qualification
0.5.0      First production-oriented stable
1.0.0rc1   Public API freeze
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
