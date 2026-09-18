# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** Sessions + Credentials alpha (`0.3.0a2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.3.0a2` adds the first framework-neutral **Authentication** bounded context on top of the durable persistence introduced in `0.3.0a1`.

Authentication remains deliberately separate from authorization:

```text
Identity
   ↓
Credential reference / external authenticator
   ↓
AuthenticationContext
(method + AAL + MFA + provider/device/network)
   ↓
Session
   ↓
AuthorizationEngine
```

The core does **not** store raw passwords, API keys, client secrets or bearer tokens. A `Credential` stores only an opaque reference to externally protected secret material plus non-secret metadata such as type, fingerprint, label, validity and status.

```python
credential = authentication.register_credential(
    identity_id=identity.id,
    credential_type=CredentialType.PASSKEY,
    reference="vault://iam/credentials/passkey/alice",
    fingerprint="sha256:example-public-fingerprint",
)

session = authentication.open_session(
    identity_id=identity.id,
    method=AuthenticationMethod.PASSKEY,
    assurance_level=AssuranceLevel.AAL2,
    mfa=True,
    expires_at=clock.now() + timedelta(hours=8),
)
```

The resulting `AuthenticationContext` is token-format agnostic. JWT issuance and validation are intentionally deferred to `0.3.0b1`, so the future JWT adapter can consume Session state instead of defining authentication semantics itself.

SQLAlchemy adapters persist Credentials and Sessions on SQLite/PostgreSQL while preserving caller-owned transactions.

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

## Authentication guarantees in 0.3.0a2

- active Identity required before credential registration or session creation;
- no raw secret persistence in Credential;
- duplicate credential references rejected;
- UTC-aware temporal invariants;
- explicit credential validity windows;
- explicit session expiration;
- irreversible credential/session revocation;
- bulk revocation of all active sessions for an Identity;
- expired or revoked artifacts excluded from active queries;
- authentication method, assurance level and MFA state preserved across persistence;
- SQLite repository conformance plus live PostgreSQL qualification;
- caller-owned SQLAlchemy transactions;
- runtime version and wheel metadata checked for coherence.

`create_schema()` and `drop_schema()` remain alpha bootstrap helpers. Production database migrations, password hashing, JWT, federation and distributed revocation are separate future milestones.

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
