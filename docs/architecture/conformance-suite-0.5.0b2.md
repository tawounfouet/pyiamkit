# Conformance Suite — 0.5.0b2

## Purpose

PyIAMKit 0.5.0b2 turns adapter compatibility from repository-specific tests into
reusable, executable conformance contracts.

The target milestone contains these suites:

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
- consume an adapter-specific probe/factory rather than import one concrete backend;
- return a deterministic structured report;
- identify each failed contract by name;
- be reusable by official and third-party adapters;
- fail closed when adapter behavior is ambiguous or violates the contract;
- remain separate from performance benchmarking and vendor certification.

## Structured reports

The public conformance surface starts with:

```text
ConformanceCheck
ConformanceReport
ConformanceFailure
```

A report contains the suite name, target adapter name and uniquely named checks.
Consumers may inspect the report or call `require_passed()` to turn any failed
check into a release-blocking `ConformanceFailure`.

## RepositoryConformance

The first reusable suite is driven by `RepositoryProbe`.

Current baseline checks are:

```text
missing_read_returns_none
round_trip_preserves_state
round_trip_returns_copy
exists_tracks_persistence
save_is_snapshot_isolated
loaded_value_is_snapshot_isolated
rehydration_invariant
```

Optional probe callbacks enable only the checks supported by the repository port.

The suite requires database-like snapshot behavior when
`require_copy_semantics=True`: neither mutating the caller-owned object after
`save()` nor mutating a loaded object may silently modify already-persisted state.

## Initial certification targets

LOT-C2-01 qualifies the same reusable suite against:

```text
InMemoryIdentityRepository
SqlAlchemyIdentityRepository[SQLite]
```

A deliberately non-conforming aliasing repository is also tested. It stores and
returns caller-owned object references and must fail the suite, proving that the
harness detects violations rather than merely producing a green report.

## CI

The dedicated `official-conformance` CI job is the release gate for the reusable
suite package. It is intentionally separate from the historical adapter-specific
conformance jobs.

As the milestone progresses, the official job will expand to run the remaining
M20 suites while the existing integration/conformance jobs remain valuable
implementation-level qualification.

## Non-goals

The conformance API does not:

- benchmark adapter performance;
- certify external vendors;
- guarantee production readiness by itself;
- replace integration tests against PostgreSQL, Redis, Django, FastAPI or SCIM;
- permit a backend to weaken core security semantics through capability flags.

Production qualification remains the next milestone, 0.5.0rc1.
