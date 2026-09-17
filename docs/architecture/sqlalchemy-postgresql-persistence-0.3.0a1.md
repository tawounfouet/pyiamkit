# SQLAlchemy / PostgreSQL Persistence — 0.3.0a1

## Objective

`0.3.0a1` introduces durable persistence while preserving PyIAMKit's dependency rule:

```text
adapters -> application -> domain
```

The Identity, Tenancy, Authorization and Audit bounded contexts remain independent from SQLAlchemy and PostgreSQL. Existing repository protocols are unchanged; the new package implements them as optional infrastructure adapters.

## Package boundary

```text
pyiamkit/
├── identity/
├── tenancy/
├── authorization/
├── audit/
└── persistence/
    └── sqlalchemy/
        ├── database.py
        ├── schema.py
        ├── common.py
        ├── identity.py
        ├── tenancy.py
        ├── authorization.py
        └── audit.py
```

Importing `pyiamkit` does not import SQLAlchemy. Consumers opt in with `pyiamkit[sqlalchemy]` or `pyiamkit[postgres]`.

## Transaction model

Repositories receive a caller-owned `sqlalchemy.orm.Session`.

```text
Application transaction
        ↓
SQLAlchemy Session
        ├── IdentityRepository.save()
        ├── MembershipRepository.save()
        ├── RoleBindingRepository.save()
        └── AuditRepository.append()
        ↓
commit / rollback decided by caller
```

Repositories never call `commit()`. This allows a host application to compose several IAM mutations atomically and to decide how domain-event publication participates in its own transaction strategy.

## Storage model

### Identity

`iam_identities` stores the Identity aggregate root. Human or service-account profile data is stored as extensible JSON, while lifecycle fields remain first-class columns. External identity links are normalized into `iam_identity_external_links` so provider/subject lookup is indexed and unique.

### Tenancy

`iam_tenants` stores tenant lifecycle state. `iam_memberships` stores the subject/tenant relationship, validity interval and optional organization identifier, with a database uniqueness constraint on `(identity_id, tenant_id)`.

### Authorization

The authorization catalog uses relational structures:

```text
iam_permissions
      ↑
iam_role_permissions
      ↓
iam_roles
      ↓
iam_role_parents
```

Role inheritance is therefore represented as a directed graph rather than serialized inside a role payload. RoleBindings are stored in `iam_role_bindings` with an explicit tenant scope and temporal validity.

### Governance

`iam_constraints` persists deny-only resource constraints. `iam_sod_rules` persists both static mutually-exclusive role rules and dynamic distinct-actor rules using a discriminator column.

### Audit

`iam_audit_events` is append-only from the repository API perspective. Duplicate event identifiers are rejected. Query indexes cover chronological, subject and correlation-ID access patterns.

## PostgreSQL mapping

Portable SQLAlchemy types are used where possible. PostgreSQL receives:

- native `UUID` identifiers;
- timezone-aware timestamps;
- `JSONB` for extensible profile, metadata and audit payloads;
- relational foreign keys and partial unique indexes for role naming rules.

SQLite uses the same logical schema with emulated UUID and JSON support and is the fast conformance backend in the regular Python 3.12/3.13 CI matrix.

## Role name uniqueness

Role names are case-insensitive within their namespace:

- global roles are unique among global roles;
- tenant roles are unique within a tenant;
- identical tenant role names may exist in different tenants.

The schema uses partial unique indexes for global and tenant-scoped role namespaces.

## Serialization boundary

Domain metadata permits extensible Python values, but SQL JSON columns require JSON-safe payloads. The SQLAlchemy adapter validates metadata at its boundary and raises `PersistenceSerializationError` rather than silently stringifying arbitrary Python objects.

This keeps persistence conversion explicit and prevents lossy round-trips from becoming invisible application behavior.

## Schema lifecycle

`create_schema()` and `drop_schema()` exist for:

- local development;
- examples;
- SQLite conformance tests;
- isolated integration environments.

They are not positioned as a production migration system. Alembic-style versioned migration management is intentionally deferred until the persistence model has completed its alpha qualification.

## CI qualification

Two levels are required:

### SQLite conformance

The normal Python 3.12 and 3.13 matrix installs `pyiamkit[sqlalchemy]` and verifies:

- Identity and external-link round-trips;
- User and ServiceAccount profile persistence;
- Tenant and Membership round-trips;
- Permission, Role, hierarchy and RoleBinding persistence;
- constraint and SoD rule persistence;
- append-only Audit behavior;
- caller-controlled rollback;
- PostgreSQL DDL compilation for UUID/JSONB.

### Live PostgreSQL

A dedicated PostgreSQL 16 service installs `pyiamkit[postgres]` and executes an end-to-end persisted authorization flow:

```text
Identity
  ↓
Tenant
  ↓
Membership
  ↓
Permission + Role
  ↓
RoleBinding
  ↓
AuthorizationEngine
  ↓
ALLOW
  ↓
AuditEvent
```

The test then opens a new database session and verifies that the Identity, RoleBinding and authorization audit record are durable.

## Security properties

- database FKs reinforce aggregate references;
- no repository performs an implicit commit;
- audit IDs are immutable/unique;
- tenant identifiers are first-class columns rather than buried in JSON;
- external identity provider subjects are globally unique at the database layer;
- resource attributes are still excluded from authorization audit records before persistence;
- persistence does not create any authorization bypass path.

## Deferred work

The following remain outside `0.3.0a1`:

- production migration tooling;
- optimistic-lock enforcement using aggregate `version` columns;
- async SQLAlchemy repositories;
- connection-pool operational tuning;
- PostgreSQL row-level security;
- cache invalidation / Redis;
- sessions and credentials;
- JWT and web-framework integrations.

Those concerns can be added without changing the domain repository contracts established before the persistence milestone.
