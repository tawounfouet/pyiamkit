# Stable Public API — 1.0.0

## Purpose

PyIAMKit 1.0.0 promotes the fully qualified 1.0.0rc1 public-contract freeze to the
first stable public API.

This promotion introduces no new IAM capability, no public-contract expansion and
no business-schema migration.

## Stable contract baseline

The 1.0.0 stable contract is the exact reviewed RC baseline:

```text
docs/api/public-api-freeze-1.0.0rc1.json
```

That manifest remains authoritative for the initial 1.x compatibility line.

The stable contract includes:

```text
documented public import locations
exports
constructor/function signatures
public methods/properties
enum values
dataclass fields
public exception codes
AuthorizationReason semantics
PermissionCode semantics
repository / port contracts
migration policy
event-versioning rules
```

The package version token is intentionally not frozen to one literal value.

## Promotion invariants

1.0.0 must preserve all of the following from 1.0.0rc1:

- no frozen public export removed or renamed;
- no incompatible signature drift;
- no existing exception code changed;
- no AuthorizationReason changed;
- no PermissionCode grammar or normalization changed;
- no adapter contract weakened;
- no implicit SCIM Group-to-Role mapping introduced;
- no Redis authority escalation;
- no token-authority shortcut over durable Session state;
- no persistence business-schema change.

## Persistence

The current schema baseline remains:

```text
0001_0_5_0rc1_baseline
```

The transition from 1.0.0rc1 to 1.0.0 requires no new database migration.

## Release gates

The exact stable commit must pass:

```text
CI
Security
Production Qualification
API Compatibility
```

Release qualification continues to cover Python 3.12/3.13, SQLite, PostgreSQL,
Redis, FastAPI, Django, OIDC, MFA, SCIM, audit/outbox, conformance, supply-chain
evidence and installed-package smoke/examples.

## Compatibility policy

The 1.x compatibility and deprecation policy is defined in:

```text
docs/api/compatibility-policy-1.0.md
```

Breaking public-contract changes normally require the next major version.

Security fixes may tighten unsafe behavior without preserving an insecure
compatibility bug.

## Supported/non-goals

1.0.0 is a stable public API, not a claim that every IAM feature or vendor adapter
exists.

Explicitly unsupported unless added in a later compatible release:

- refresh-token lifecycle;
- delegation;
- HSM/KMS custody supplied by PyIAMKit itself;
- cryptographic audit-log immutability;
- exactly-once external event delivery;
- arbitrary historical multi-revision database downgrade;
- implicit external Group-to-Role mapping.

## Release meaning

`1.0.0` means:

```text
Stable Public API
Stable Authorization Semantics
Stable Tenant Model
Stable Error Codes
Stable Repository Contracts
Stable Migration Policy
Stable Event Versioning Rules
Production Security Baseline
Official Conformance Suite
Executable API Compatibility Gate
```
