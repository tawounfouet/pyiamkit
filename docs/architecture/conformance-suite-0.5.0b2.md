# Conformance Suite — 0.5.0b2

## Purpose

PyIAMKit `0.5.0b2` turns adapter compatibility from repository-specific tests into
reusable, executable conformance contracts.

The milestone implements the eight M20 suites:

```text
RepositoryConformance
AuthorizationConformance
TenantIsolationConformance
AuthenticationConformance
TokenProviderConformance
PolicyEvaluatorConformance
SecretStoreConformance
EventPublisherConformance
```

## Design principles

A conformance suite must:

- be framework-neutral;
- consume adapter/application-specific probes rather than own deployment wiring;
- return a deterministic structured report;
- identify every failed contract by a stable check name;
- be reusable by official and third-party adapters;
- fail closed when behavior is ambiguous or violates PyIAMKit semantics;
- remain separate from performance benchmarking and vendor certification.

## Structured reports

The common reporting surface is:

```text
ConformanceCheck
ConformanceReport
ConformanceFailure
```

A report contains the suite name, target name and uniquely named checks.
`require_passed()` turns any failed check into a release-blocking
`ConformanceFailure`.

## RepositoryConformance

`RepositoryProbe` supplies create/identifier/save/get/snapshot callbacks and
optional mutation, exists and rehydration assertions.

Baseline checks:

```text
missing_read_returns_none
round_trip_preserves_state
round_trip_returns_copy
exists_tracks_persistence
save_is_snapshot_isolated
loaded_value_is_snapshot_isolated
rehydration_invariant
```

The suite requires database-like snapshot behavior when
`require_copy_semantics=True`: neither mutating the caller-owned object after
`save()` nor mutating a loaded object may silently modify persisted state.

Initial official targets:

```text
InMemoryIdentityRepository
SqlAlchemyIdentityRepository[SQLite]
```

A deliberately aliasing repository is also qualified negatively and must fail.

## AuthorizationConformance

`AuthorizationProbe` supplies fresh semantic scenarios.

Checks:

```text
matching_grant_allows
no_binding_denies
unregistered_permission_denies
inactive_subject_denies
revoked_access_denies
same_context_is_semantically_deterministic
```

The suite does not compare random decision identifiers. Determinism is evaluated on
the security-relevant semantic projection of the decision.

## TenantIsolationConformance

`TenantIsolationProbe` makes Tenant isolation independently release-blocking.

Checks:

```text
same_tenant_control_allows
cross_tenant_binding_does_not_leak
foreign_tenant_role_fails_closed
scope_tenant_mismatch_rejected
```

A deliberately leaky probe is included to prove that the suite detects a
cross-Tenant authorization regression.

## AuthenticationConformance

The authentication suite qualifies Session lifecycle invariants:

```text
active_subject_opens_session
inactive_subject_cannot_open_session
revoked_session_is_inactive
expired_session_is_inactive
bulk_revocation_leaves_no_active_session
```

The initial target is `AuthenticationApplicationService` composed with the
reference in-memory repositories.

## TokenProviderConformance

The token suite qualifies trust-boundary behavior without depending on one token
format:

```text
issued_token_round_trips
tampered_token_rejected
expired_token_rejected
wrong_issuer_or_audience_rejected
revoked_session_token_rejected
```

The first official target is `JwtTokenProvider`. Invalid scenarios must surface
through `InvalidAccessToken` semantics, including its specific subclasses.

## PolicyEvaluatorConformance

PyIAMKit currently implements policy/governance semantics inside the authorization
bounded context rather than a standalone policy package. M20 therefore maps
`PolicyEvaluatorConformance` to the live constraints and SoD model.

Checks:

```text
matching_context_preserves_allow
constraint_violation_reduces_access
missing_context_fails_closed
dynamic_sod_conflict_denies
insufficient_assurance_requires_step_up
```

The suite verifies that governance can restrict an RBAC candidate allow but cannot
silently widen access.

## SecretStoreConformance

`SecretStoreProbe` qualifies the storage boundary used by MFA secret adapters:

```text
missing_reference_returns_none
put_get_round_trip
duplicate_reference_rejected
delete_removes_secret
delete_missing_is_idempotent
```

The first official target is `InMemoryMfaSecretStore`, which remains a
tests/examples reference adapter rather than a production secret vault.

## EventPublisherConformance

The event publisher suite qualifies:

```text
event_identity_preserved
duplicate_delivery_preserves_identity
invalid_event_rejected
downstream_failure_propagates
```

The initial target is `GenericSecurityEventExporter`. Stable event identity under
redelivery is essential for downstream idempotency. Adapter/downstream failures must
not be silently swallowed.

## Official conformance gate

The dedicated `official-conformance` CI job runs:

```text
tests/conformance/test_*_conformance_suite.py
```

This gate is intentionally separate from the historical adapter-specific
conformance/integration jobs. Both layers remain useful:

```text
reusable contract suites
        +
backend/framework integration qualification
```

## Third-party adapter usage

A third-party adapter should:

1. construct the appropriate probe with fresh isolated scenarios;
2. run the matching PyIAMKit conformance suite;
3. call `report.require_passed()` in its CI;
4. document any optional capabilities outside the baseline contract.

A capability flag must never weaken a baseline security invariant.

## Non-goals

The conformance API does not:

- benchmark adapter performance;
- certify external vendors;
- guarantee production readiness by itself;
- replace PostgreSQL, Redis, Django, FastAPI, OIDC or SCIM integration tests;
- provide a loophole for weakening Tenant isolation or fail-closed semantics.

Production qualification remains the next milestone, `0.5.0rc1`.
