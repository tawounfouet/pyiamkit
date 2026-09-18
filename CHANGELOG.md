# Changelog

All notable changes to PyIAMKit will be documented in this file.

The project follows Semantic Versioning and PEP 440 for Python pre-releases.

## [Unreleased]

## [0.4.0a1] - 2026-09-18

### Added

- Framework-neutral external identity federation contracts in `pyiamkit.authentication`.
- `FederatedIdentityClaims`, `IdentityTokenVerifier`, `FederatedAssuranceResolver` and `FederatedAuthenticationService`.
- Local federation flow resolving trusted external identities exclusively through existing `(provider_id, external_subject)` links.
- Optional `pyiamkit[oidc]` extra and static-key OIDC ID Token verifier.
- OIDC validation for issuer, client audience, signature, required claims, expiration, issued-at time, optional nonce and authorized-party semantics.
- Explicit ACR/AMR to PyIAMKit assurance mapping through `StaticOidcAssuranceResolver`.
- OIDC-created local Sessions using `AuthenticationMethod.OIDC` and preserving provider/authentication context.
- Security tests for issuer/audience mismatch, nonce mismatch, multiple audiences, `azp`, algorithm confusion, `kid`, subject constraints and temporal validation.
- Federation tests proving that verified email claims never auto-link a different external subject.

### Security

- External identity resolution uses provider ID plus OIDC `sub`; email is never an identity key.
- No external Role, group or arbitrary claim becomes a PyIAMKit RoleBinding or Permission automatically.
- OIDC signing algorithm is fixed by trusted verifier configuration, not selected from the token header.
- A configured key set requires a known `kid` and fails closed for missing or unknown key identifiers.
- Expected OIDC nonce values are compared against the verified ID Token and mismatch fails closed.
- Multiple-audience ID Tokens require a matching `azp`.
- Assurance mapping is explicit and provider-configured; unrecognized ACR defaults conservatively to AAL1 and MFA is false unless configured AMR values match.
- Unlinked or locally inactive Identities cannot establish a PyIAMKit Session.

## [0.3.0b2] - 2026-09-18

### Added

- Optional FastAPI integration under `pyiamkit.integrations.fastapi`.
- `bearer_authentication()` dependency factory using FastAPI's HTTP Bearer security scheme and PyIAMKit's `TokenProvider`.
- `require_permission()` dependency factory connecting verified token claims to the existing `AuthorizationEngine`.
- Explicit application-provided Tenant, Scope, Resource and correlation-ID resolver contracts.
- OpenAPI bearer-security integration through FastAPI's native security dependency system.
- End-to-end FastAPI tests covering Identity, Tenant, Membership, RoleBinding, Session, JWT and Authorization.
- FastAPI example with authenticated and authorized endpoints.

### Security

- Missing or invalid bearer credentials return HTTP 401 with `WWW-Authenticate: Bearer`.
- Authentication failures expose a generic response and do not leak token-validation internals.
- Authorization denials return HTTP 403 without converting them into authentication failures.
- FastAPI never decodes JWTs directly; token verification remains delegated to the configured `TokenProvider`.
- FastAPI never evaluates RBAC itself; authorization remains delegated to the existing default-deny `AuthorizationEngine`.
- Session revocation therefore invalidates previously issued bearer JWTs at the HTTP boundary as well.

## [0.3.0b1] - 2026-09-18

### Added

- Framework-neutral access-token contracts: `TokenProvider`, `AccessTokenClaims`, `IssuedAccessToken`, `TokenId` and token-specific errors.
- Optional `pyiamkit[jwt]` extra using PyJWT with cryptographic algorithm support.
- `JwtTokenProvider` adapter for signed access JWT issuance and verification.
- Minimal access-token claims linking subject, Session, authentication time, assurance level, authentication method and MFA state.
- Configurable issuer, audience, access-token TTL and clock leeway.
- Optional `kid`-based verification-key selection for signing-key rotation.
- Session-aware verification: a cryptographically valid JWT is rejected when its referenced Session is missing, expired or revoked.
- Access-token expiration is capped by the durable Session expiration.
- Executable JWT lifecycle example and security-focused JWT tests.

### Security

- Allowed JWT algorithms are configured out-of-band and never selected from an untrusted token header.
- Issuer and audience validation are mandatory.
- Unknown or missing `kid` values fail closed when a verification key set is configured.
- Tokens do not carry Roles or Permissions as an authorization source of truth.
- JWT verification cross-checks subject, Session ID, assurance level, authentication method, MFA state and authentication time against the durable Session.
- Access JWTs are the only token type in this milestone; refresh-token rotation and reuse detection are intentionally not simulated without durable server-side state.

## [0.3.0a2] - 2026-09-18

### Added

- Dedicated `pyiamkit.authentication` bounded context for credential and authenticated-session lifecycle.
- `Credential` aggregate with opaque secret references, fingerprints, validity windows, revocation and expiration.
- `Session` aggregate with explicit expiration, last-activity tracking, revocation reason and authentication context.
- `AuthenticationContext` carrying authentication method, assurance level, MFA state, provider, device and network-zone metadata.
- Authentication methods for password, API key, certificate, passkey, OIDC, SAML and external providers.
- Assurance levels `AAL1`, `AAL2` and `AAL3` as framework-neutral authorization context.
- `AuthenticationApplicationService` enforcing active-Identity prerequisites, duplicate-reference rejection and bulk session revocation.
- InMemory Credential and Session repository reference adapters.
- SQLAlchemy Credential and Session repositories with portable SQLite/PostgreSQL schema.
- SQL constraints for credential/session validity windows and foreign-key ownership by Identity.
- Live PostgreSQL persistence coverage for Credential and Session round-trips in the end-to-end authorization scenario.
- Runtime/package version coherence check in the post-build smoke test.

### Security

- Credential persistence stores only opaque references and optional fingerprints; raw passwords, API keys, client secrets and equivalent secret material are explicitly out of scope.
- Session persistence stores authentication context and lifecycle state but no bearer token material.
- Credential/session revocation is irreversible at the aggregate level.
- Expired credentials and sessions are excluded from active repository queries.

## [0.3.0a1] - 2026-09-17

### Added

- Optional `pyiamkit.persistence.sqlalchemy` adapter bundle without introducing SQLAlchemy into the core dependency set.
- SQLAlchemy repositories for Identity, Tenant, Membership, Permission, Role, RoleBinding, constraints, SoD rules and append-only Audit events.
- Portable SQL schema using UUID identifiers and timezone-aware timestamps, with PostgreSQL `JSONB` for extensible JSON payloads.
- Explicit caller-owned transaction semantics: repositories execute writes but never commit application transactions.
- Schema bootstrap helpers for development and test environments.
- `sqlalchemy` and `postgres` installation extras.
- SQLite repository-conformance tests covering aggregate round-trips, updates, governance, audit and transaction rollback.
- Live PostgreSQL 16 CI gate using psycopg and an end-to-end persisted authorization decision.
- SQLAlchemy persistence example and architecture documentation.

## [0.2.0b2] - 2026-09-17

### Added

- Dedicated append-only `pyiamkit.audit` bounded context.
- Immutable `AuditEvent` records, audit categories/outcomes, `AuditSink` and queryable `AuditRepository` ports.
- InMemory append-only audit repository reference adapter.
- `DomainEventAuditBridge` for projecting domain events into the audit stream.
- Stable `AuthorizationDecisionId` on every runtime authorization decision.
- `AuthorizationDecisionAuditRecorder` for minimal decision audit projection.
- Optional `audit_sink` integration in `AuthorizationEngine` covering both ALLOW and DENY decisions.
- Audit minimization: authorization audit records include resource type/identifier but never copy resource attribute payloads.
- Summary and detailed decision explanation projections through `ExplanationLevel` and `DecisionExplanation`.
- `AuthorizationEngine.describe()` while preserving the existing `explain()` contract.
- Audit and explainability unit tests.

## [0.2.0b1] - 2026-09-17

### Added

- Restrictive runtime authorization constraints evaluated after RBAC permission resolution.
- Framework-neutral `ResourceDescriptor` for tenant-bound protected-resource context.
- `NumericMaximumConstraint` and `ResourceAttributeEqualsConstraint` built-in rules.
- Static Separation of Duties through `MutuallyExclusiveRolesRule`.
- Dynamic Separation of Duties through `DistinctActorSoDRule` for maker-checker style workflows.
- Static SoD enforcement before RoleBinding persistence, including inherited effective Roles.
- Runtime defensive static-SoD validation and dynamic SoD checks.
- Fail-closed behavior when required governance context is missing or malformed.
- `matched_rule_id` provenance and structured governance denial reason codes.
- Constraint and SoD repository ports with InMemory reference adapters.
- `AccessGovernanceApplicationService`, evaluator services, conformance tests and architecture documentation.

## [0.2.0a2] - 2026-09-17

### Added

- Hierarchical RBAC with transitive Role inheritance.
- `RoleHierarchyResolver` for ancestor, role-path and effective-permission resolution.
- `RoleHierarchyApplicationService` for guarded parent-role mutations.
- Cycle detection and bounded hierarchy traversal.
- Tenant-safe inheritance: tenant Roles may inherit global Roles, while cross-tenant and global-to-tenant inheritance are rejected.
- Fail-closed authorization when hierarchy references missing, disabled, cyclic or otherwise invalid Roles.
- Distinct direct and inherited authorization reason codes.
- `bound_role_id` and `matched_role_id` in authorization decisions to distinguish the bound Role from the Role contributing a permission.
- Hierarchy-focused unit tests and architecture documentation.

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
