# Security Policy

PyIAMKit is security-sensitive software. Please avoid reporting suspected vulnerabilities in a public GitHub issue.

## Supported versions

PyIAMKit 1.x is the current supported stable release line.

Only the most recent supported 1.x release is expected to receive security fixes.
Pre-release builds and older 1.x versions should be upgraded after a security fix
unless a release note or security advisory explicitly states otherwise.

The 0.5.x pre-1.0 line is superseded by 1.x and should be upgraded.

## Reporting a vulnerability

Use a private GitHub security advisory for this repository when available, or contact the maintainer privately through an established channel. Include enough information to reproduce and assess the issue without publishing exploit details publicly.

## Security principles

PyIAMKit is designed around default deny, least privilege, explicit tenant boundaries, strong revocation semantics, no raw secrets in logs, and fail-closed behavior for critical security uncertainty.


## Security qualification gates

The repository Security workflow includes independent release-blocking gates for:

- static source analysis with Bandit;
- property-based authorization invariants;
- third-party dependency vulnerability auditing;
- full-history secret scanning;
- bounded hostile-input fuzz targets;
- targeted mutation tests for critical authorization/authentication controls;
- JWT/OIDC key-rotation behavior;
- privileged MFA and break-glass controls.

The standard CI additionally qualifies supported Python versions, PostgreSQL,
Redis, Django, FastAPI and SCIM integrations.

## Privileged access baseline

Sensitive Role assignment is fail-closed and requires an explicitly configured
privileged-action policy hook. The reference guard requires an identified actor,
MFA and AAL2 or stronger assurance, and refuses sensitive Role self-assignment.
Exceptional self-assignment requires an explicit stronger approval guard supplied
by the host application.

MFA step-up rotates the Session identifier rather than elevating the existing
Session in place.

Break-glass activation is temporary and auditable. It does not automatically create
a RoleBinding or bypass normal authorization. Activation must be recorded through
the configured security-evidence sink before it is considered successful.

## Supply-chain baseline

GitHub Actions used by the Security workflow are pinned to immutable revisions.
The supported third-party dependency surface is vulnerability-audited, and Git
history is scanned for secrets. A release must not treat failure or uncertainty in
these gates as success.

## Production operations

Production deployments should additionally follow:

- `docs/guides/security-operations.md`;
- `docs/guides/production-deployment.md`;
- `docs/guides/production-checklist.md`;
- `docs/guides/persistence-migration-and-rollback.md`.

1.0.0 is production-stable but does not provide HSM/KMS custody supplied by
PyIAMKit itself, cryptographic audit-log immutability, exactly-once external event
delivery, refresh-token lifecycle, delegation or implicit external Group-to-Role
mapping. These must not be inferred from the stable label.
