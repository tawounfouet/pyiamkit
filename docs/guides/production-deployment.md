# Production deployment guide — PyIAMKit 0.5.0

## Scope

PyIAMKit 0.5.0 is the first production-oriented stable release.

It is intended for:

- real applications;
- controlled production deployments;
- API feedback before 1.0;
- official and third-party adapter qualification.

It is still pre-1.0. Public API compatibility is therefore governed by the
documented 0.5.x contracts, not by the 1.0 freeze policy.

## Reference architecture

A production deployment typically looks like:

```text
FastAPI / Django / service application
                |
             PyIAMKit
                |
        PostgreSQL authority
                |
      Redis optional projection
                |
        Outbox publisher
                |
      SIEM / monitoring sink
```

PostgreSQL is the recommended authoritative persistence backend for controlled
production use. Redis is optional derived infrastructure and must never replace
authoritative IAM repositories or SecurityState.

## Minimal deployment

Small applications may use:

```text
Application
    |
 PyIAMKit
    |
SQLite
```

SQLite is qualified by the regular conformance and production lifecycle gates, but
operators must still evaluate concurrency, backup and availability requirements for
their workload.

## Required production dependencies

Choose only the extras required by the host application.

Examples:

```bash
python -m pip install "pyiamkit[postgres]"
python -m pip install "pyiamkit[jwt,fastapi,postgres,redis]"
python -m pip install "pyiamkit[oidc,oidc-http,django,postgres]"
```

Production secret custody must use a host-selected protected secret store. The
reference in-memory MFA secret store is for tests/examples and is not a production
vault.

## Database deployment

For a fresh or qualified 0.5.0b2-compatible database, use the versioned migration
baseline:

```python
from pyiamkit.persistence.sqlalchemy import (
    create_sqlalchemy_engine,
    migrate_schema,
)

engine = create_sqlalchemy_engine(DATABASE_URL)
result = migrate_schema(engine)
print(result.version)
```

Do not use `drop_schema()` as a production deployment or rollback mechanism.

See `persistence-migration-and-rollback.md` for the exact migration and rollback
contract.

## Distributed operations

Redis adapters are optional and provide derived:

- authorization cache;
- revocation registry;
- SecurityState projections;
- invalidation Pub/Sub.

A Redis outage or uncertain distributed state must not manufacture a trusted ALLOW.
The distributed runtime falls back to authoritative evaluation or fails closed
according to its contract.

## Audit and SIEM

For security-sensitive production workloads:

- persist AuditEvent and OutboxEvent in the same caller-owned transaction;
- publish committed outbox entries after commit;
- preserve stable security-event IDs;
- configure consumer idempotency;
- monitor failed/retrying outbox entries;
- route security events to an appropriate sink.

At-least-once delivery is intentional. Exactly-once external delivery is not
claimed.

## Authentication and keys

Production deployments should:

- keep Session persistence authoritative;
- enable MFA for privileged administration;
- rotate Session identifiers after MFA step-up;
- maintain explicit JWT/OIDC key identifiers;
- operate a documented signing-key rotation procedure;
- protect private signing material outside application source control.

PyIAMKit qualifies key-selection and rotation behavior but does not provide HSM/KMS
custody.

## Deployment sequence

Recommended sequence:

1. build or obtain the exact qualified package artifact;
2. verify artifact checksum/provenance when available;
3. back up the authoritative database;
4. stop or drain incompatible writers if required;
5. run `migrate_schema()`;
6. deploy the application;
7. run smoke import and health checks;
8. exercise one known ALLOW and one known DENY authorization path;
9. verify Session revocation;
10. verify Audit/Outbox delivery and security monitoring;
11. resume normal traffic.

## Rollback

For 0.5.0rc1/0.5.0, the business schema is unchanged and the RC1 migration baseline
remains valid.

Application rollback therefore normally means:

- stop/drain writers;
- restore the previously qualified application package;
- keep the compatible business schema;
- validate authorization and Session health;
- resume traffic.

Database snapshot/point-in-time restore remains the safety mechanism for a future
schema-changing migration that cannot be downgraded safely.

## Required monitoring

At minimum monitor:

- authorization failures and unexpected deny spikes;
- Session revocation failures;
- migration errors;
- Audit/Outbox persistence failures;
- outbox retry backlog;
- Redis unavailability when Redis is enabled;
- OIDC/JWKS refresh failures;
- privileged-action and break-glass security events;
- dependency/security workflow failures for future upgrades.

## Stable does not mean 1.0

0.5.0 is stable enough for controlled production use, but the formal public API
freeze is planned for 1.0.0rc1. Consumers should pin compatible versions and review
the changelog before upgrading within the pre-1.0 line.
