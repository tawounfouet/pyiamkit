# Persistence bootstrap, migration and rollback — 0.5.0rc1

## Status

PyIAMKit 0.5.0rc1 introduces the first explicit SQLAlchemy migration baseline.

The supported lifecycle is now:

- `create_schema()` — unversioned bootstrap helper for tests/local/disposable environments;
- `migrate_schema()` — production-facing RC1 baseline adoption/stamping helper;
- `current_schema_version()` — migration-ledger inspection;
- `rollback_schema_baseline()` — non-destructive removal of the RC1 baseline stamp;
- `drop_schema()` — destructive teardown helper for isolated environments.

The migration ledger is stored in:

```text
iam_schema_migrations
```

The RC1 baseline identifier is:

```text
0001_0_5_0rc1_baseline
```

## 0.5.0b2 → 0.5.0rc1 adoption

The persistence business schema is unchanged between the qualified 0.5.0b2
baseline and RC1.

For a database that already contains the complete compatible PyIAMKit schema,
`migrate_schema()`:

1. detects the existing PyIAMKit tables;
2. refuses a partially present schema;
3. creates migration bookkeeping;
4. records the RC1 baseline;
5. preserves existing business data.

This adoption path is qualified on SQLite and PostgreSQL.

## Fresh database

For an empty database:

```text
empty database
    ↓
migrate_schema()
    ↓
create current PyIAMKit schema
    ↓
create iam_schema_migrations
    ↓
stamp 0001_0_5_0rc1_baseline
```

Calling `migrate_schema()` again is idempotent.

## Fail-closed migration state

Migration does not guess how to repair ambiguous state.

It fails closed when:

- only part of the expected PyIAMKit table set exists;
- the migration ledger contains an unknown version.

The RC1 adoption check validates the expected table set. It does not perform a
full column/constraint diff against arbitrary historical schemas. Operators should
only adopt a database known to originate from the qualified 0.5.0b2 schema.

## Rollback model

### RC1 → 0.5.0b2

Because RC1 introduces migration bookkeeping without a business-schema change,
`rollback_schema_baseline()` removes only the RC1 migration stamp.

It preserves:

- IAM tables;
- Identity/Tenant/Role/Binding data;
- Session/Credential/MFA data;
- Audit/Outbox data;
- SecurityState and provisioning data.

After un-stamping, a previously qualified 0.5.0b2 application can continue to use
the unchanged business schema.

### Transaction rollback

Repository writes still do not commit implicitly. Host applications control commit
and rollback boundaries, including AuditEvent + OutboxEvent transaction composition.

This transaction rollback is distinct from release/schema rollback.

### Future schema-changing migrations

RC1 establishes migration bookkeeping, not a complete multi-revision migration
framework.

The current implementation does not yet provide:

- arbitrary ordered DDL revisions beyond the RC1 baseline;
- column rename/backfill transforms;
- general downgrade DDL;
- online migration orchestration;
- automatic compatibility inference for unknown historical schemas.

A future schema-changing release must add an explicit forward revision plus
qualified rollback/restore behavior.

## Destructive helper policy

`drop_schema()` is suitable only for:

- tests;
- local development;
- disposable qualification databases;
- explicit teardown tooling.

It must never be used as an automatic production rollback mechanism.

## Emergency restore

For a failed future deployment that changes persisted structure incompatibly:

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

Backup/restore remains a host deployment/database responsibility.

## RC qualification evidence

The RC qualification suite verifies on SQLite and PostgreSQL that:

- a fresh database can be migrated and stamped;
- a compatible 0.5.0b2 schema can be adopted without data loss;
- migration is idempotent;
- rollback removes only the RC1 baseline stamp;
- data remains readable after rollback;
- the baseline can be reapplied;
- a partial schema fails closed;
- unknown migration history fails closed;
- bootstrap teardown/recreate remains valid in disposable environments.
