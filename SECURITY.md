# Security Policy

PyIAMKit is security-sensitive software. Please avoid reporting suspected vulnerabilities in a public GitHub issue.

## Supported versions

The project is currently pre-alpha. Until a stable support policy is published, only the most recent release is expected to receive security fixes.

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
MFA and AAL2 or stronger assurance.

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
