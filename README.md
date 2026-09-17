# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** SQLAlchemy persistence alpha (`0.3.0a1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.3.0a1` introduces the first durable persistence layer without making SQLAlchemy a core dependency.

The existing domain ports remain unchanged:

```text
Domain / Application
       ↓
Repository Protocols
       ↓
┌──────────────────────┬─────────────────────────┐
│ InMemory adapters    │ SQLAlchemy adapters     │
│ tests / local logic  │ SQLite / PostgreSQL     │
└──────────────────────┴─────────────────────────┘
```

The SQLAlchemy bundle persists the current Identity, Tenancy, Authorization, governance and Audit models. Repository instances receive an existing SQLAlchemy `Session`; they execute reads/writes but never commit the caller's transaction.

```python
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyIdentityRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)

engine = create_sqlalchemy_engine("postgresql+psycopg://user:pass@localhost/iam")
create_schema(engine)  # bootstrap/testing during the alpha line
SessionFactory = create_session_factory(engine)

with SessionFactory.begin() as session:
    identities = SqlAlchemyIdentityRepository(session)
    identities.save(identity)
```

PostgreSQL uses native UUID columns and JSONB for extensible JSON payloads. SQLite remains supported as a lightweight conformance/test backend.

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
AuthorizationRequest
       ↓
Identity + Tenant + Membership
       ↓
RoleBinding + Role Hierarchy
       ↓
Constraints + SoD
       ↓
AuthorizationDecision
       ├── DecisionExplanation
       └── AuditSink

Persistence ports
       ↓
SQLAlchemy Session
       ↓
SQLite / PostgreSQL
```

The domain contexts do not import SQLAlchemy, psycopg, PostgreSQL drivers or database models. Persistence adapters depend inward on domain contracts, never the reverse.

## Persistence guarantees in 0.3.0a1

- caller-owned transactions;
- repository round-trip conformance on SQLite;
- live PostgreSQL 16 CI qualification;
- UUID identifiers and timezone-aware timestamps;
- PostgreSQL JSONB for extensible payloads;
- append-only Audit semantics;
- foreign keys and relational role/permission/hierarchy tables;
- no implicit commits inside repositories.

`create_schema()` and `drop_schema()` are alpha bootstrap helpers. A production migration workflow is intentionally deferred to a later persistence-hardening milestone.

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
