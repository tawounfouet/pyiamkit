# Persistence migration and rollback — 0.5.0rc1

## Status

PyIAMKit 0.5.0rc1 introduces the first explicit SQLAlchemy schema-version
baseline.

The production-oriented persistence helpers are:

```text
migrate_schema()
current_schema_version()
rollback_schema_baseline()
```

The baseline revision is:

```text
0001_0_5_0rc1_baseline
```

Migration history is stored in:

```text
iam_schema_migrations
```

`create_schema()` remains an idempotent bootstrap helper for tests and local
development. Production deployments should use `migrate_schema()` so schema
state is explicit and validated.

## RC1 migration model

### Empty database

```text
empty database
    ↓
migrate_schema()
    ↓
create current IAM schema
    ↓
create iam_schema_migrations
    ↓
stamp 0001_0_5_0rc1_baseline
```

### Compatible 0.5.0b2 database

The persistence structure did not change between the qualified 0.5.0b2 schema and
the RC1 business schema. RC1 therefore supports a non-destructive baseline
adoption:

```text
complete 0.5.0b2-compatible IAM schema
    +
no migration ledger
    ↓
migrate_schema()
    ↓
validate every expected IAM table is present
    ↓
preserve existing data
    ↓
create migration ledger
    ↓
stamp RC1 baseline
```

This exact path is qualified on SQLite and PostgreSQL with persisted Identity data.

### Partial or unknown schema

Migration fails closed when:

- only a subset of expected PyIAMKit tables is present;
- the migration ledger contains an unknown revision.

PyIAMKit does not attempt speculative DDL repair or silently reinterpret an
unrecognized migration history.

## Idempotency

Calling `migrate_schema()` again on an already stamped RC1 database performs no
new migration and returns an unapplied result.

The schema version remains:

```text
0001_0_5_0rc1_baseline
```

## Rollback model

### RC1 → 0.5.0b2-compatible application rollback

RC1 adds migration bookkeeping but no incompatible business-table change relative
to the qualified 0.5.0b2 schema.

`rollback_schema_baseline()` therefore performs a non-destructive unstamp:

```text
RC1 baseline
    ↓
remove 0001_0_5_0rc1_baseline row
    ↓
preserve IAM tables
    ↓
preserve IAM data
    ↓
previous compatible application can be redeployed
```

The rollback qualification explicitly verifies that persisted Identity data
survives the unstamp.

Removing the stamp is not the same as automatically downgrading arbitrary future
schema changes.

### Transaction rollback

Repository writes do not commit implicitly. The host application retains
transaction ownership, so IAM state, AuditEvent and OutboxEvent writes can be
rolled back atomically before commit.

This is separate from release/schema rollback.

### Emergency restore

For a future migration that changes stored structure incompatibly:

```text
stop writers
    ↓
capture diagnostics
    ↓
restore database snapshot / point-in-time backup when required
    ↓
deploy previously qualified package
    ↓
run smoke + tenant-isolation + authorization checks
    ↓
resume traffic
```

The database backup/restore mechanism remains a host deployment responsibility.

## Destructive helper policy

`drop_schema()` removes PyIAMKit business tables and migration bookkeeping. It is
appropriate only for:

- tests;
- local development;
- disposable qualification databases;
- explicit teardown tooling.

It is never an automatic production rollback mechanism.

## What RC1 does not claim

The RC1 baseline is intentionally narrow. It does not claim:

- migration from arbitrary historical PyIAMKit schemas;
- online column/table transformations;
- automatic data backfills;
- automatic downgrade of future structural migrations;
- zero-downtime migration orchestration.

Future schema-changing releases must add ordered revisions, forward migration
evidence from the prior supported revision, data-preservation assertions and an
explicit downgrade or restore strategy.

## RC qualification evidence

The Production Qualification workflow verifies:

- empty-database migration and baseline stamping on SQLite;
- migration idempotency;
- non-destructive adoption of a complete 0.5.0b2-compatible schema on SQLite;
- the same adoption and rollback path on PostgreSQL 16;
- persisted data survives adoption and RC1 baseline rollback;
- partial schemas fail closed without a migration stamp;
- unknown migration history fails before business-schema DDL;
- legacy `create_schema()` bootstrap remains idempotent for disposable/local use.

This is the migration contract qualified by 0.5.0rc1.
