# Public API Freeze — 1.0.0rc1

## Purpose

PyIAMKit 1.0.0rc1 freezes the public contract that 1.0.0 is expected to preserve.

This milestone adds no new IAM feature. Its job is to make the existing contract
explicit, reviewable and executable.

## Frozen namespaces

The freeze covers 27 documented public namespaces.

Package surfaces driven by explicit `__all__` include the core bounded contexts,
reference in-memory adapters, conformance API and SQLAlchemy bundle.

Optional modules that intentionally expose public symbols without `__all__` are
frozen from the names already documented in `PUBLIC_API.md`:

```text
pyiamkit.authentication.adapters.jwt
pyiamkit.authentication.adapters.oidc
pyiamkit.authentication.adapters.oidc_discovery
pyiamkit.authentication.adapters.totp
pyiamkit.operations.adapters.redis
pyiamkit.integrations.fastapi
pyiamkit.integrations.fastapi_scim
pyiamkit.integrations.django
```

The machine-readable baseline is:

```text
docs/api/public-api-freeze-1.0.0rc1.json
```

## What the fingerprint freezes

For every public export, the executable contract records enough structure to detect
accidental compatibility drift:

```text
export name
callable / constructor signature
public class method signatures
properties
enum member names and values
dataclass field names/types/default presence
public exception codes
stable exported constant values where representable
```

The root `__version__` export is intentionally treated as a version token rather
than freezing its literal value.

## Compatibility gate

The dedicated `API Compatibility` workflow runs on Python 3.12 with the complete
qualified optional adapter dependency surface installed.

It performs two independent checks:

1. semantic audit of public exceptions, AuthorizationReason and PermissionCode;
2. exact comparison with the committed RC manifest.

A missing/renamed export, signature change, enum/reason-code change, dataclass field
change, exception-code change or reviewed constant change blocks the RC until the
change is explicitly reconciled.

## Public vs internal

The freeze does not make every importable object public.

Not frozen unless explicitly listed:

- names beginning with `_`;
- nested implementation modules that are not documented as import locations;
- helper functions omitted from public `__all__`;
- third-party framework objects merely imported internally;
- test/support helpers;
- implementation details of SQLAlchemy models/tables;
- Redis client implementation details.

Consumers should import from the documented public namespaces instead of reaching
through internal module paths.

## M23 review disposition

The freeze review found no need for disruptive public symbol renaming.

The material corrections made before freezing are contract hardening:

- stable codes added to public token errors;
- stable codes added to persistence errors;
- schema migration error aligned to PersistenceError and given a stable code;
- ConformanceFailure given a stable code;
- DjangoAuthenticationRequired aligned to AuthenticationError and given a stable
  code;
- base PyIAMKitError and DomainError given stable codes;
- stale “alpha” labels removed from current Identity/Tenancy surfaces.

Authorization reason values and PermissionCode grammar remain unchanged.

No pending public deprecation exists at the start of 1.0.0rc1.

## RC rule

After this baseline is finalized, RC changes are limited to:

- bug fixes;
- security fixes;
- compatibility fixes;
- documentation corrections;
- qualification/release fixes.

Any public-contract change requires explicit baseline review and cannot be hidden as
an internal refactor.

## Exit to 1.0.0

1.0.0 may be promoted only when the same final commit is green for:

```text
CI
Security
Production Qualification
API Compatibility
```

The 1.0.0 promotion itself should not add a new major capability.
