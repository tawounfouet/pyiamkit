# Security Hardening — 0.5.0b1

## Purpose

PyIAMKit `0.5.0b1` applies the security and threat-model backlog as executable
qualification gates and explicit framework-neutral security contracts.

The milestone does not make external infrastructure authoritative for IAM. It
hardens the boundaries around the existing domain and adapters.

## Implemented lots

```text
LOT-C1-01  Property-Based Security Invariants
LOT-C1-02  Supply-Chain Security Gates
LOT-C1-03  Bounded Hostile-Input Fuzz Targets
LOT-C1-04  Targeted Security Mutation Gate
LOT-C1-05  Rate-Limit Ports
LOT-C1-06  Session Fixation Protection
LOT-C1-07  Key Rotation Hardening
LOT-C1-08  Admin MFA Hooks
LOT-C1-09  Break-Glass Foundations
```

## Property-based invariants

Hypothesis generates bounded authorization scenarios proving that:

- a binding from Tenant A never authorizes Tenant B;
- revoking a RoleBinding never increases access;
- a disabled Identity never authorizes;
- expired Membership or RoleBinding access never authorizes;
- scope/tenant mismatch is rejected before authorization evaluation.

These are behavioral invariants, not examples tied to one fixed identifier.

## Supply-chain gates

The Security workflow now includes:

```text
Bandit
dependency audit
Git-history secret scan
pinned GitHub Actions revisions
```

The dependency audit installs the full supported extras surface, removes the local
editable PyIAMKit package from the environment, then audits the resolved third-party
packages. This avoids treating the source checkout itself as a registry dependency.

The secret scan reads full Git history and is a release-blocking Security job.

## Bounded hostile-input fuzzing

The CI fuzz subset uses Hypothesis with finite example budgets and no wall-clock
fuzz loop. Current targets are:

```text
JWT compact token input
OIDC ID Token input
SCIM User JSON payload
SCIM filter expression
PermissionCode parsing
```

Untrusted input must either produce a valid canonical object or fail through the
documented protocol/domain error. Internal parser errors must not leak as accepted
input.

## Targeted mutation qualification

`scripts/security_mutation_gate.py` temporarily weakens production guards and
requires their sentinel tests to fail.

Current mutants cover:

```text
scope / tenant guard
inactive subject guard
dynamic SoD guard
revoked Session guard
OIDC issuer validation
```

The original source is restored in a `finally` boundary after every mutation probe.
A surviving mutant fails the Security workflow.

This is intentionally a focused security mutation subset rather than a claim of
exhaustive mutation coverage.

## Rate-limit port

The Authentication public API exposes:

```text
RateLimitKey
RateLimitPolicy
RateLimitDecision
RateLimiter
RateLimitGuard
RateLimitError
RateLimitExceeded
RateLimitUnavailable
```

`RateLimiter.check_and_consume()` is atomic by contract. PyIAMKit does not mandate
an in-memory, Redis, gateway or vendor-specific implementation.

`RateLimitGuard` fails closed:

- a denied decision raises `RateLimitExceeded`;
- backend unavailability propagates as a security failure;
- invalid cost or clock state is rejected;
- an unavailable limiter never becomes an implicit ALLOW.

## Session fixation protection

MFA step-up no longer elevates the same Session identifier.

```text
AAL1 Session
     │
     │ valid MFA proof
     ▼
revoke old Session
     │
     ▼
open new SessionId
AAL2 + MFA
```

The replacement Session preserves the original authentication context where
appropriate and never outlives the previous Session expiration.

The old access token fails because its Session is revoked. New access tokens are
issued only against the rotated Session.

## Key rotation hardening

JWT key rotation explicitly qualifies:

```text
old key active
     ↓
old + new overlap
     ↓
new key only
```

During overlap, both known `kid` values verify. After retirement, the old `kid`
fails closed immediately. Unknown key identifiers never fall back to another key.

OIDC Discovery/JWKS qualification also covers bounded unknown-`kid` refresh,
cooldown behavior, signing-key rotation and rejection of private/symmetric material
from remote JWKS.

## Privileged administration MFA hook

Sensitive Role assignment is now guarded separately from ordinary Role assignment.

`RoleBindingApplicationService` accepts an optional `PrivilegedActionGuard`.
Ordinary non-sensitive Roles preserve their existing behavior.

For a Role where `role.sensitive is True`:

- a privileged-action guard is mandatory;
- an explicit actor is mandatory;
- authentication evidence is mandatory;
- MFA is mandatory;
- the configured minimum assurance level is mandatory.

The reference `MfaPrivilegedActionGuard` defaults to AAL2 + MFA.

Absence of a guard is not interpreted as “no policy”: sensitive assignment fails
closed.

## Break-glass foundations

Break-glass access is deliberately **not** modeled as an automatic RoleBinding or
AuthorizationEngine bypass.

The framework-neutral surface is:

```text
BreakGlassGrantId
BreakGlassPolicy
BreakGlassGrant
BreakGlassActivationSink
BreakGlassService
BreakGlassError
BreakGlassDenied
```

Activation requires:

- explicit actor;
- explicit Tenant;
- MFA authentication evidence;
- configured minimum assurance;
- non-empty justification;
- positive bounded duration;
- mandatory recording through `BreakGlassActivationSink`.

A successful activation emits a CRITICAL `BreakGlassActivated` SecurityEvent.

If security evidence cannot be recorded, activation does not return successfully.

A `BreakGlassGrant` contains no Role, Permission or RoleBinding. Host applications
must still make an explicit, audited decision about how emergency context is used.

## Security workflow gates

The dedicated workflow is organized around independent jobs:

```text
static-security
authorization-properties
dependency-audit
secret-scan
hostile-input-fuzz
targeted-security-mutations
key-rotation-security
privileged-access-security
```

These run in addition to the normal CI matrix, PostgreSQL qualification, Redis live
qualification, Django, FastAPI and SCIM compatibility gates.

## Threat-model delta

The milestone directly strengthens these classes of risk:

```text
cross-tenant authorization regression
revocation regression
scope widening
SoD bypass
revoked-session acceptance
OIDC issuer validation removal
hostile parser/input handling
dependency vulnerability exposure
secret leakage in Git history
authentication brute-force integration boundary
Session fixation after privilege elevation
signing-key retirement
sensitive Role administration
emergency privileged access
```

## Non-goals

`0.5.0b1` does not claim:

- exactly-once security-event delivery;
- a built-in distributed rate-limit backend;
- HSM/KMS ownership of signing keys;
- automatic privileged-role approval workflows;
- automatic authorization bypass for break-glass;
- exhaustive mutation testing of every line;
- unbounded continuous fuzzing.

Those concerns remain adapter, deployment or later production-qualification work.
