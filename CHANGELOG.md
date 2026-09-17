# Changelog

All notable changes to PyIAMKit will be documented in this file.

The project follows Semantic Versioning and PEP 440 for Python pre-releases.

## [Unreleased]

## [0.2.0a1] - 2026-09-17

### Added

- First runtime `AuthorizationEngine` with explicit default-deny semantics.
- Structured `AuthorizationRequest` and `AuthorizationDecision` contracts.
- Deterministic ALLOW/DENY reason codes and explanation paths.
- Runtime validation of active Identity, Tenant, Membership, RoleBinding and Role state.
- Permission-catalog validation before role-permission matching.
- TenantScope enforcement and fail-closed behavior for unavailable or tenant-incompatible roles.
- `authorize()`, `can()`, `require()` and `explain()` APIs.
- Structured `AuthorizationDenied` exception carrying the denied decision.
- Unit tests and executable runtime authorization example.

## [0.1.0b2] - 2026-09-17

### Added

- `RoleBinding` aggregate connecting an Identity to a Role in an explicit TenantScope.
- Binding lifecycle with suspension, reactivation, revocation and temporal validity.
- Validation of active Identity, Tenant and Membership before role assignment.
- Tenant-bound role compatibility and direct-assignability enforcement.
- Tenant-partitioned RoleBinding repository port and InMemory adapter.
- Cross-tenant and duplicate-binding security tests.

## [0.1.0b1] - 2026-09-17

### Added

- Stable permission-code value object using the `resource.action` convention.
- Immutable Permission catalog entries.
- Role aggregate with explicit type, status, sensitivity, assignability and optional tenant scope.
- Strict add/remove permission semantics and domain events.
- Role and Permission repository ports plus InMemory adapters.
- Role catalog application service and repository conformance tests.
- Explicit guarantee that roles contain capabilities but grant nothing before RoleBindings exist.

## [0.1.0a2] - 2026-09-17

### Added

- Tenancy bounded context with Tenant, Membership and Organization models.
- Explicit Tenant and Membership lifecycle state machines.
- `TenantContext`, `TenantScope` and `TenantIsolationGuard`.
- Tenant-aware repository ports and InMemory adapters.
- Active Identity + Tenant + Membership validation before tenant context resolution.
- Cross-tenant isolation and repository conformance tests.
- Shared `DomainEventSink` port for bounded contexts.

## [0.1.0a1] - 2026-09-17

### Added

- Initial Identity bounded context.
- `IdentityId`, `IdentityType`, `IdentityStatus` and `EmailAddress` value objects.
- User and ServiceAccount profiles.
- Explicit Identity lifecycle state machine and domain events.
- External identity linking keyed by provider plus external subject.
- `IdentityRepository` port and database-like InMemory adapter.
- `IdentityApplicationService` and InMemory event sink.
- Unit and repository-conformance tests.
- Executable basic Identity example and guide.

## [0.0.1] - 2026-09-17

### Added

- Initial repository structure using a `src/` layout.
- Package metadata and build configuration.
- Ruff, mypy, pytest and coverage configuration.
- Minimal shared kernel primitives.
- CI, security and release-validation workflows.
- Public API manifest, security policy and contribution guide.
