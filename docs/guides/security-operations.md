# Security operations guide — PyIAMKit 0.5.0

## Security model

PyIAMKit operates on these principles:

```text
default deny
least privilege
explicit Tenant boundary
authoritative revocation
fail closed on critical uncertainty
auditable privileged changes
no raw secrets in telemetry
```

The host application remains responsible for protecting the infrastructure and for
not introducing bypass paths around PyIAMKit authorization.

## Tenant isolation

Treat Tenant identity as a security boundary.

Operational rules:

- never infer the current Tenant from mutable global process state;
- construct explicit Tenant-aware scopes;
- reject scope/Tenant mismatches;
- keep tenant identifiers explicit in persistence and audit records;
- include cross-Tenant negative tests for host-specific authorization wrappers.

PyIAMKit's property and conformance suites make cross-Tenant leakage
release-blocking for the qualified framework surface.

## Secrets

Do not store raw production secrets in:

- source code;
- logs;
- AuditEvent payloads;
- SecurityEvent payloads;
- application configuration committed to Git.

Use opaque secret references and an external secret-management system for protected
material. The in-memory MFA store is not a production vault.

## Signing keys

Maintain:

- explicit key IDs;
- documented active/overlap/retired states;
- bounded overlap during rotation;
- secure private-key custody;
- monitoring for unknown-key and JWKS failures.

Unknown or retired `kid` values must not fall back to an unrelated trusted key.

## Sessions and tokens

Access tokens remain subordinate to authoritative Session state.

Production operations should verify:

- revoked Sessions invalidate associated access tokens;
- Session expiry is enforced;
- MFA step-up rotates SessionId;
- emergency revocation procedures exist;
- durable Session storage is backed up consistently with IAM state.

## Privileged administration

Sensitive Role assignment requires an explicit privileged-action guard.

The reference guard expects:

- identified actor;
- MFA;
- AAL2 or stronger by default;
- no sensitive Role self-assignment.

Applications with approval workflows may supply a stronger guard. They should not
weaken the baseline silently.

## Break-glass

Break-glass activation must remain:

- temporary;
- justified;
- MFA protected;
- assurance constrained;
- recorded through the mandatory evidence sink;
- visible to monitoring.

A BreakGlassGrant is emergency context, not a hidden RoleBinding or authorization
bypass.

## Distributed infrastructure

Redis is optional derived state.

Operational uncertainty in cache/revocation projections must never be interpreted
as permission to reuse a stale ALLOW. Alert on repeated fallback, unstable state or
revocation-registry unavailability.

## Audit and outbox

Security operations should monitor:

- append failures;
- transaction rollback rates;
- outbox FAILED/PENDING age;
- repeated delivery attempts;
- SIEM sink failures;
- duplicate consumer side effects.

Duplicate delivery is possible under at-least-once semantics. Deduplicate on the
stable security-event ID.

## Dependency and source security

Before adopting an upgrade, require the exact candidate commit to pass:

- Bandit;
- dependency vulnerability audit;
- full-history Gitleaks scan;
- authorization property tests;
- hostile-input fuzzing;
- targeted mutation gates;
- key-rotation qualification;
- privileged-access qualification.

## Incident response

For a suspected IAM bypass:

1. stop the affected privileged operation where feasible;
2. preserve logs/audit/outbox evidence;
3. revoke affected Sessions/credentials;
4. rotate compromised keys/secrets;
5. identify affected Tenant/scope boundaries;
6. restore authoritative state if corruption occurred;
7. validate known DENY and revocation paths;
8. only then resume normal privileged operations.

## Residual risks in 0.5.0

0.5.0 does not claim built-in:

- refresh-token lifecycle;
- delegation;
- HSM/KMS custody;
- cryptographically tamper-evident audit logs;
- exactly-once external event delivery;
- database row-level security;
- arbitrary multi-revision migration/downgrade orchestration.

Deployments must not treat these as implemented merely because 0.5.0 is
production-oriented stable.
