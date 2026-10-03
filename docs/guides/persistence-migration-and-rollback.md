# Persistence bootstrap, migration and rollback — 0.5.0rc1

## Status

PyIAMKit 0.5.0rc1 qualifies the current SQLAlchemy schema lifecycle honestly:

- `create_schema()` is an idempotent bootstrap helper;
- `drop_schema()` is a destructive teardown helper for isolated environments;
- repositories keep transaction ownership with the caller;
- there is no built-in versioned migration engine in 0.5.0rc1.

This document is intentionally explicit because production qualification must not
turn a bootstrap helper into a fictional migration system.

## Supported schema lifecycle in the RC

```text
empty database
    │
    ▼
create_schema()
    │
    ├── create PyIAMKit tables / indexes / constraints
    │
    └── preserve existing compatible objects on repeated calls
    │
    ▼
application transactions
```

A repeated `create_schema()` call is qualified on SQLite and PostgreSQL and must
not drop existing PyIAMKit data.

## What create_schema() is not

`create_schema()` does not:

- diff one released schema against another;
- rename or transform existing columns;
- backfill data;
- run ordered migration revisions;
- track a migration version table;
- provide downgrade scripts.

Deployments that require online schema evolution must manage that evolution outside
the current core package until PyIAMKit ships a versioned migration contract.

## Rollback model

Rollback depends on the kind of change.

### Application-code rollback without schema change

When the target PyIAMKit versions share the same persistence schema:

1. stop or drain writers;
2. preserve a database backup/snapshot;
3. deploy the previous application/package version;
4. run its smoke and authorization health checks;
5. resume writers.

No `drop_schema()` call is part of this path.

### Schema-changing upgrade

For any future release that changes persisted structure, the release must provide a
documented forward migration and rollback/restore procedure before it can satisfy
the production gate.

Until that capability exists, an operator must not assume that installing an older
wheel automatically downgrades the database.

### Emergency restore

For a failed deployment where persisted state may have changed incompatibly:

```text
stop writers
    ↓
capture failed-state diagnostics
    ↓
restore database snapshot / point-in-time backup
    ↓
deploy previously qualified package
    ↓
run smoke + tenant-isolation + authorization checks
    ↓
resume traffic
```

The backup/restore mechanism belongs to the host deployment/database platform.

## Destructive helper policy

`drop_schema()` is suitable only for:

- tests;
- local development;
- disposable qualification databases;
- explicit teardown tooling.

It must never be used as an automatic production rollback mechanism.

## Transaction rollback

Repository writes do not commit implicitly. Host applications control commit and
rollback boundaries, allowing IAM state, AuditEvent and OutboxEvent changes to be
rolled back atomically before commit.

This transactional rollback is distinct from release/schema rollback.

## RC qualification evidence

The RC qualification suite verifies on SQLite and PostgreSQL that:

- first bootstrap creates the expected IAM schema;
- repeated bootstrap is idempotent;
- data survives a repeated bootstrap;
- destructive teardown removes PyIAMKit tables;
- a clean schema can be recreated after teardown.

These checks validate the current bootstrap contract only. They do not claim
previous-version-to-RC structural migration support.

## Gate for future schema changes

A future release that modifies the persistence schema must add, before release:

- a schema revision identifier;
- forward migration evidence from the prior supported release;
- data-preservation assertions;
- rollback or backup/restore instructions;
- PostgreSQL qualification;
- SQLite qualification where SQLite remains supported;
- an explicit incompatibility note when downgrade is impossible.

Without those items, the migration gate is not satisfied.
