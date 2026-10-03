# Threat Model Delta — 0.5.0rc1

## Purpose

This document reviews the security delta between the original PyIAMKit threat model
and the production-qualification release candidate.

It is not a replacement for the main threat model. It records which controls now
exist, which threats are outside the implemented feature surface, and which
residual risks remain deployment responsibilities.

## Implemented security delta

### Cross-Tenant authorization

Controls now include:

- explicit Tenant IDs throughout Membership, RoleBinding and authorization requests;
- scope/Tenant validation before authorization evaluation;
- property-based cross-Tenant invariants;
- dedicated TenantIsolationConformance;
- persistence columns/indexes that keep Tenant identity explicit.

Residual deployment risk: host applications must not bypass PyIAMKit authorization
with unrelated application-side privilege paths.

### Stale distributed privilege

Controls now include:

- monotonic SecurityState;
- derived authorization-cache validation against authoritative state;
- Redis invalidation plus deny-fast revocation overlays;
- fail-closed behavior when distributed state is unavailable or unstable;
- live Redis qualification.

Redis remains derived operational infrastructure, not IAM authority.

### Audit and publication failures

Controls now include:

- append-only audit repository semantics;
- transactional AuditEvent + OutboxEvent intent;
- caller-owned business transaction boundaries;
- post-commit at-least-once publication;
- stable event identity for consumer idempotency;
- retryable failures;
- vendor-neutral SIEM export;
- raw-secret payload redaction.

Residual risk: external delivery is not exactly-once and audit storage is not
cryptographically tamper-evident.

### Authentication/session elevation

Controls now include:

- durable Session authority for access tokens;
- revoked Session token rejection;
- MFA step-up with SessionId rotation;
- key rotation overlap/retirement qualification;
- OIDC issuer/audience/JWKS validation;
- bounded hostile-input fuzzing.

Refresh-token rotation/reuse detection is not claimed because PyIAMKit does not
currently expose a refresh-token feature.

### Privileged administration

Controls now include:

- sensitive Role marker;
- fail-closed privileged-action hook;
- MFA/AAL2 reference guard;
- self-assignment denial in the reference guard;
- temporary break-glass evidence with bounded duration;
- mandatory CRITICAL security-event recording.

Residual risk: approval workflows and operator identity governance remain host
application concerns unless implemented by an explicit custom guard.

### Policy and SoD

Controls now include:

- deny-only constraints;
- static and dynamic SoD;
- assurance/MFA constraints;
- targeted mutation tests for critical policy checks;
- PolicyEvaluatorConformance.

There is no separate Policy Administration API that silently bypasses these
contracts. Host applications that expose policy mutation must apply their own
privileged administration controls and audit.

### Supply chain

Controls now include:

- Bandit source scan;
- strict dependency vulnerability audit;
- full-history Gitleaks scan;
- pinned actions in the Security workflow;
- wheel/sdist build + install smoke;
- release SHA-256 checksums;
- CycloneDX SBOM;
- build provenance metadata.

Artifact signing remains a future capability.

## Original threat register disposition

| ID | Threat | RC disposition |
| --- | --- | --- |
| T-001 | Cross-Tenant authorization | controlled by Tenant isolation invariants/conformance |
| T-002 | Refresh-token replay | feature not implemented; no support claim |
| T-003 | Privileged Role self-assignment | reference privileged guard denies it |
| T-004 | Policy tampering | policy semantics fail closed; host admin surface remains deployment concern |
| T-005 | Audit alteration | append-only API semantics; cryptographic tamper evidence not implemented |
| T-006 | ServiceAccount secret leak | opaque secret references; secret custody remains external |
| T-007 | OIDC issuer spoof | issuer/audience/signature/JWKS qualification |
| T-008 | Stale cached privilege | SecurityState + invalidation + revocation overlay |
| T-009 | Scope widening | explicit scope/Tenant validation + conformance |
| T-010 | Delegation amplification | delegation feature not implemented; no support claim |

## Production residual risks

The RC does not claim to solve:

- refresh-token lifecycle;
- delegation;
- HSM/KMS key custody;
- cryptographic audit-log immutability;
- exactly-once external event delivery;
- database row-level security;
- versioned schema migrations;
- multi-region consensus for revocation/state;
- host-application authorization bypasses outside PyIAMKit.

These are not silently marked as mitigated.

## Critical-risk review

No new critical risk is intentionally accepted inside the implemented qualified
surface.

This statement depends on the final RC head passing:

- Security workflow;
- TenantIsolationConformance;
- dependency audit;
- secret scan;
- privileged-access gates;
- Audit/Outbox qualification;
- Production Qualification.

A failing final-head gate invalidates this review until resolved.
