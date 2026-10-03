# First Production-Oriented Stable — 0.5.0

## Status

PyIAMKit 0.5.0 is the first production-oriented stable release.

It promotes the fully qualified 0.5.0rc1 line without adding a new IAM feature.

The promotion means:

- the 0.5.x operational/security/conformance baseline is complete;
- real applications and controlled production use are supported targets;
- adapter qualification is public and reusable;
- production deployment guidance is available;
- the release remains pre-1.0 and therefore is not the final public API freeze.

## Promotion baseline

0.5.0 inherits the exact qualified capability line from 0.5.0rc1:

```text
Identity / Tenancy
RBAC / hierarchical roles / SoD / constraints
Authorization + explainability
SQLAlchemy / SQLite / PostgreSQL
Sessions / Credentials / JWT
FastAPI / Django
OIDC / Discovery / JWKS
MFA / step-up
SCIM Users / Groups / provider profiles
Distributed SecurityState / Redis
Audit / transactional outbox / SIEM
Security hardening
Official conformance suites
RC1 migration baseline
```

No IAM feature is introduced by the stable promotion itself.

## Stable promotion gates

The stable commit must pass on the same exact head:

```text
CI
Security
Production Qualification
```

This includes:

- Python 3.12 and 3.13;
- Ruff / format / mypy strict;
- unit/integration tests and coverage threshold;
- official conformance;
- PostgreSQL;
- Redis;
- Django 5.2 / 6.1;
- FastAPI / SCIM;
- Entra / Okta qualification;
- dependency/secret/static security gates;
- property, fuzz, mutation, privileged-access and key-rotation gates;
- SQLite/PostgreSQL migration qualification;
- package artifacts, checksums, SBOM and provenance;
- performance sanity.

## Persistence compatibility

0.5.0 keeps the RC1 migration baseline:

```text
0001_0_5_0rc1_baseline
```

There is no business-schema change between 0.5.0rc1 and 0.5.0.

A database successfully migrated/stamped by RC1 does not require a second migration
revision merely because the Python package version becomes 0.5.0.

## Production documentation

The stable line provides:

```text
docs/guides/production-deployment.md
docs/guides/security-operations.md
docs/guides/persistence-migration-and-rollback.md
docs/guides/integrations.md
docs/guides/production-checklist.md
```

These guides complement the executable qualification workflows. They do not replace
host-specific architecture, regulatory or risk review.

## Support posture

0.5.0 is pre-1.0. Consumers should:

- pin compatible versions;
- review CHANGELOG before upgrades;
- run adapter/application conformance in their own CI;
- keep production rollback and backup procedures current.

Security fixes are expected to target the most recent supported 0.5.x release.

## Non-claims

0.5.0 does not claim:

- final 1.0 API stability;
- refresh-token lifecycle;
- delegation;
- HSM/KMS custody;
- cryptographic audit-log immutability;
- exactly-once external event delivery;
- arbitrary historical multi-revision schema migration/downgrade;
- host-specific regulatory compliance.

## Next milestone

The next roadmap milestone is:

```text
1.0.0rc1 — Public API Freeze
```

That milestone is contract-focused: API inventory, naming, exceptions, reason codes,
permission naming, adapter contracts and deprecation cleanup.
