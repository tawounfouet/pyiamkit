# Production Qualification — 0.5.0rc1

## Objective

PyIAMKit 0.5.0rc1 is a feature-freeze and production-qualification release
candidate.

No new IAM feature is introduced by this milestone. The purpose is to prove that
the implemented 0.5.x surface is coherent across supported runtimes, persistence,
framework integrations, distributed operations, provisioning, security and release
artifacts.

## Required workflows

A release-candidate commit is qualified only when all three workflow families are
green on that exact commit:

```text
CI
Security
Production Qualification
```

A green result on an older commit is evidence for that older commit only.

## M21 qualification matrix

| Surface | Qualification evidence |
| --- | --- |
| Python 3.12 | CI quality matrix |
| Python 3.13 | CI quality matrix |
| InMemory | unit + official conformance suites |
| SQLite | SQLAlchemy conformance + RC schema lifecycle |
| PostgreSQL 16 | live PostgreSQL integration + RC schema lifecycle |
| FastAPI | FastAPI SCIM integration gate |
| Django 5.2 | Django compatibility gate |
| Django 6.1 | Django compatibility gate |
| OIDC | unit/security key-rotation and Discovery/JWKS qualification |
| Redis 7 | live Redis qualification |
| Audit | unit/conformance + PostgreSQL transactional qualification |
| Outbox | unit/conformance + PostgreSQL delivery/atomicity qualification |
| SCIM | FastAPI, Group, provider-profile, Entra and Okta qualification |
| Package install | built wheel reinstall + smoke import |
| Examples | all executable examples in CI |
| Release artifacts | wheel + sdist + SHA-256 + SBOM + provenance |
| Performance sanity | 1,000 InMemory authorization decisions within a coarse 10 s budget |
| Schema lifecycle | SQLite + PostgreSQL repeated bootstrap/teardown proof |

## M21 release gates

```text
[x] unit tests green
[x] integration tests green
[x] conformance green
[x] tenant isolation green
[x] security tests green
[ ] migration/bootstrap qualification green on final RC head
[x] rollback strategy documented/reviewed
[x] docs baseline defined
[x] examples are executable CI gates
[x] package installation is an executable CI gate
[x] performance sanity gate defined
[x] threat-model delta documented
```

The migration/bootstrap item remains unchecked until the dedicated Production
Qualification workflow is green on the final RC head.

## Migration terminology

The current SQLAlchemy contract exposes `create_schema()` and `drop_schema()`.

For 0.5.0rc1:

- repeated bootstrap is qualified;
- teardown/recreate is qualified in disposable databases;
- transactional rollback is qualified;
- versioned schema migrations are not implemented.

Therefore this RC does not claim automatic upgrade/downgrade between arbitrary
historical schemas.

See
`docs/guides/persistence-migration-and-rollback.md`.

## Release artifact evidence

The Production Qualification workflow builds the actual wheel and sdist and
generates:

```text
SHA256SUMS
sbom.cdx.json
provenance.json
```

The SBOM uses CycloneDX 1.5 and records the package plus declared direct/optional
dependency requirements. Provenance records the source commit, workflow/run,
builder, Python/platform metadata and artifact digests.

PyPI publication remains deliberately separate. A green RC qualification is not a
claim that an artifact was published.

## Rollback gate

The RC rollback review distinguishes:

1. transaction rollback before commit;
2. application rollback when schema is unchanged;
3. database restore when a schema-changing release cannot be downgraded safely.

`drop_schema()` is never an automatic production rollback strategy.

## Feature freeze rule

After 0.5.0rc1 starts, changes should be limited to:

- qualification failures;
- documentation corrections;
- security fixes;
- packaging/release fixes;
- compatibility corrections necessary to satisfy the frozen 0.5 contract.

New IAM capabilities belong after the production-stable decision or in the next
planned release line.

## Exit criteria

0.5.0rc1 can be closed only when:

- CI is green on the final head;
- Security is green on the final head;
- Production Qualification is green on the final head;
- no known critical vulnerability remains in the qualified surface;
- the production qualification and threat-model documents match the implemented
  repository state;
- release artifacts are buildable and verifiable from the final head.

The next milestone is 0.5.0, First Production-Oriented Stable.
