# Changelog

All notable changes to PyIAMKit will be documented in this file.

The project follows Semantic Versioning and PEP 440 for Python pre-releases.

## [Unreleased]

## [0.4.0b7] - 2026-09-18

### Added

- Framework-neutral SCIM Group provisioning with a dedicated `ProvisioningGroup` aggregate.
- Source- and Tenant-scoped Group membership referencing active managed `ProvisioningUser` resource IDs.
- `ScimGroupProvisioningService` for create, get, list, replace, PATCH and delete lifecycle orchestration.
- SCIM Group representations for `displayName`, `externalId`, `members.value`, rendered `members.$ref` and member display values.
- Group PATCH support for display-name changes, external ID changes, add/replace/remove members, filtered member removal and pathless replace payloads.
- Conditional SCIM discovery of Group through `/ResourceTypes` and `/Schemas`.
- Conditional protected FastAPI `/Groups` routes when a Group provisioning service is configured.
- InMemory and SQLAlchemy Group repositories.
- Portable `iam_provisioning_groups` and `iam_provisioning_group_members` persistence schema.
- SQLite repository conformance and live PostgreSQL Group/member persistence qualification.
- Generic SCIM, Microsoft Entra and Okta provider profiles marked Group-capable.
- Executable SCIM Group provisioning example and dedicated Group conformance coverage.

### Security

- A SCIM Group is a provisioning resource and never becomes a PyIAMKit Role implicitly.
- Group membership does not grant Permissions or create RoleBindings.
- Every Group member must resolve to an active managed User from the same provisioning source and Tenant.
- Nested SCIM Groups are deliberately unsupported in this milestone.
- Group DELETE tombstones the Group and clears its membership set without deleting Users, disabling Identities or changing Tenant Membership state.
- External Group names are never matched to Role names as an authorization shortcut.
- Provider-specific schema extensions are not interpreted as authorization truth.
- Group PUT, PATCH and DELETE preserve fail-closed ETag / If-Match behavior.

## [0.4.0b6] - 2026-09-18

### Added

- Explicit immutable SCIM interoperability profiles for Generic SCIM, Microsoft Entra and Okta.
- `ScimProviderKind`, `ScimProviderProfile`, `ScimDeprovisionMode` and `scim_provider_profile()`.
- Provider-aware filter parsing while preserving the strict Generic SCIM default.
- `ScimUserFilterExpression` for bounded multi-clause equality filters.
- Microsoft Entra compatibility for unquoted `externalId`/user lookup values and bounded `and` expressions.
- Okta compatibility preset retaining quoted `userName eq "..."` lookup behavior.
- Quote-aware conjunction parsing so string values containing the word `and` are not split.
- Provider-profile qualification tests and executable Entra/Okta example.

### Security

- Provider profiles tune protocol compatibility only; they never create Roles, Permissions, Memberships or authorization grants.
- Generic SCIM remains strict and does not inherit Microsoft Entra parsing relaxations.
- Okta remains strict for quoted filter values and does not inherit Entra-specific syntax.
- Only `userName` and `externalId` equality clauses are supported; OR, NOT, arbitrary attributes and relational operators remain rejected.
- Unquoted filter values are accepted only by profiles that opt in explicitly.
- SCIM Groups remain unsupported, so no provider group can implicitly become a PyIAMKit Role.
- Password provisioning remains rejected.
- Profiles are interoperability presets, not vendor certification claims.

## [0.4.0b5] - 2026-09-18

### Added

- Framework-neutral `ScimHttpTransport` translating SCIM 2.0 HTTP semantics into the existing provisioning application service.
- SCIM media type, error envelope, ServiceProviderConfig, ResourceTypes and Schemas discovery representations.
- HTTP lifecycle support for User POST, GET, filtered list, PUT, PATCH and DELETE.
- User payload parsing with explicit schema validation and rejection of unsupported password provisioning.
- Bounded filter support for `userName eq "..."` and `externalId eq "..."`.
- Configurable `maxResults` with one-based SCIM pagination.
- Resource `Location` and `ETag` response headers.
- HTTP error mapping for uniqueness, not-found, stale preconditions, invalid values and invalid PATCH paths.
- Protected FastAPI SCIM router under `pyiamkit.integrations.fastapi_scim`.
- Discovery and end-to-end FastAPI SCIM integration tests.
- Executable protected FastAPI SCIM example.

### Security

- The FastAPI SCIM router requires an explicit host-provided access dependency and does not expose anonymous provisioning routes by default.
- The transport does not authenticate or authorize provisioning clients implicitly; the host application owns that control.
- Password provisioning remains rejected.
- SCIM Groups and Group-to-Role translation remain unavailable, preventing external group names from becoming authorization truth implicitly.
- Unexpected internal exceptions map to a generic SCIM 500 error rather than exposing Python internals.
- Invalid resource identifiers map to not-found behavior without leaking parser details.
- If-Match precondition failures remain fail-closed HTTP 412 responses.

## [0.4.0b4] - 2026-09-18

### Added

- New framework-neutral `pyiamkit.provisioning` bounded context.
- Tenant-scoped `ProvisioningUser` resource mapping with stable SCIM resource ID, source-scoped `externalId`, `userName`, Membership/Identity links, active state, tombstones and weak ETag versioning.
- `ScimProvisioningService` covering User create, get, list, replace, PATCH subset and delete semantics.
- SCIM core User representations, one-based list pagination and supported PATCH operations.
- Explicit `ProvisioningSource` binding one provisioning domain to one Tenant.
- Identity User-profile replacement for provisioned display name, primary email and name attributes.
- Tenancy application operations for Membership suspension, reactivation and revocation.
- InMemory and SQLAlchemy provisioning repositories.
- Portable `iam_provisioning_users` schema with active-resource uniqueness for source + userName and source + externalId.
- ETag / If-Match optimistic concurrency checks.
- SQLite conformance and live PostgreSQL provisioning-resource persistence.

### Security

- OIDC federation links and SCIM provisioning mappings remain separate concepts.
- SCIM `externalId` is scoped to the configured provisioning source and never used as an OIDC subject.
- `active=false` suspends only the managed tenant Membership; it does not disable the global Identity.
- SCIM DELETE revokes the managed Membership and tombstones the SCIM resource without deleting the internal Identity.
- Deleted resource IDs are never reused.
- A local revoked/expired Membership is not silently reactivated by provisioning.
- SCIM group-to-Role mapping, password provisioning and arbitrary external authorization claims are not implemented in this milestone.
- If-Match mismatch fails closed with a provisioning precondition error.

## [0.4.0b3] - 2026-09-18

### Added

- Optional synchronous Django integration under `pyiamkit.integrations.django`.
- Bearer authentication helper for Django `HttpRequest`.
- `PyIAMKitAuthenticationMiddleware` for optional verified-claims attachment without globally protecting public views.
- `bearer_required()` decorator for protected synchronous views.
- `permission_required()` decorator combining verified Bearer authentication, explicit Tenant resolution and `AuthorizationEngine`.
- Helpers for reading verified claims and the final authorization decision from a request.
- Structured Django HTTP 403 step-up response matching the FastAPI assurance contract.
- Optional token-provider resolution from `settings.PYIAMKIT_TOKEN_PROVIDER`.
- Dedicated Django compatibility CI for the 5.2 and 6.1 release lines.

### Security

- Django authentication flags, groups, permissions and `is_superuser` do not bypass PyIAMKit authorization.
- Tenant resolution remains an explicit host-application resolver; arbitrary headers are not trusted as tenant authority by default.
- Missing or invalid Bearer authentication maps to HTTP 401 with `WWW-Authenticate: Bearer`.
- Ordinary authorization denial remains generic HTTP 403.
- Assurance step-up remains HTTP 403 with required AAL/MFA metadata.
- Middleware does not globally reject anonymous public requests; endpoint protection remains explicit.
- Async Django views are rejected explicitly in this sync-first adapter rather than running synchronous IAM I/O unsafely in an async context.

## [0.4.0b2] - 2026-09-18

### Added

- `AuthenticationEvidence` as a framework-neutral authorization input carrying current assurance level, MFA state and authentication time.
- `MinimumAssuranceConstraint` as a deny-only governance rule scoped by Permission and optional Tenant.
- `AccessGovernanceApplicationService.register_minimum_assurance()`.
- Distinct authorization outcomes for missing authentication evidence and insufficient assurance requiring step-up.
- `AuthorizationDecision.step_up_required`, `required_assurance_level` and `required_mfa` metadata.
- Persistence of minimum-assurance constraints in SQLite/PostgreSQL.
- FastAPI propagation of verified JWT assurance claims into `AuthorizationRequest`.
- Structured FastAPI 403 response for step-up-required decisions.
- Audit metadata for required assurance and MFA.
- End-to-end PostgreSQL qualification of a persisted AAL2+MFA authorization constraint.

### Security

- The Authorization Engine does not read Session repositories; authentication evidence is supplied explicitly by the caller.
- Minimum-assurance constraints are restrictive only and cannot create an ALLOW without an existing RBAC candidate.
- Missing authentication evidence fails closed when a permission has an assurance requirement.
- AAL and MFA requirements are evaluated independently: sufficient AAL does not satisfy a rule that also requires MFA.
- Step-up-required remains HTTP 403 in the FastAPI adapter; invalid or missing bearer authentication remains HTTP 401.
- Authorization audit records expose only required assurance metadata, not credentials, factors or secret material.

## [0.4.0b1] - 2026-09-18

### Added

- Persistent `MfaFactor` aggregate with pending, active and revoked lifecycle states.
- TOTP MFA enrollment using opaque secret references rather than raw secret persistence.
- `MfaApplicationService` for enrollment, first-code confirmation, verification, revocation and Session step-up.
- `MfaSecretStore` and `TotpProvider` ports for external secret-management integration.
- Optional `pyiamkit[mfa]` extra backed by PyOTP 2.10.x.
- Reference `PyOtpTotpProvider` and InMemory secret-store adapter for tests/examples.
- TOTP replay prevention through persisted last accepted counter.
- Session assurance step-up from AAL1 to AAL2 after a valid local TOTP factor.
- `mfa_verified_at` and `mfa_factor_id` Session authentication context.
- SQLAlchemy/SQLite/PostgreSQL persistence for MFA factors and stepped-up Sessions.
- Tests proving that an existing AAL1 JWT becomes invalid after Session step-up and a newly issued JWT carries AAL2 + MFA.

### Security

- Raw TOTP secrets are never persisted in `iam_mfa_factors`; only opaque secret references are stored.
- Pending factors cannot authenticate until a first valid TOTP code confirms enrollment.
- A TOTP counter accepted once cannot be accepted again for the same factor.
- A factor cannot step up a Session owned by another Identity.
- Revoked factors fail closed and their referenced secret is deleted through the configured secret-store adapter.
- TOTP step-up raises local Session assurance to AAL2 only; AAL3 remains reserved for stronger phishing-resistant mechanisms.
- Step-up mutates durable Session authentication state, so previously issued JWTs with stale AAL/MFA claims fail Session cross-checks.

## [0.4.0a2] - 2026-09-18

### Added

- Optional `pyiamkit[oidc-http]` extra for OIDC Discovery and remote JWKS retrieval.
- `OidcDiscoveryClient` with exact issuer validation and metadata caching.
- `OidcProviderMetadata` validation for authorization, token and JWKS endpoints plus advertised ID Token algorithms.
- `HttpxOidcTransport` reference HTTP adapter with bounded timeout, redirects disabled by default and strict JSON media-type handling.
- `JwksKeyResolver` with public signing-key parsing, five-minute default cache and controlled refresh on unknown `kid`.
- `DiscoveredOidcIdTokenVerifier` composing Discovery/JWKS infrastructure with the existing static OIDC claim verifier.
- Support for RSA/EC/EdDSA public JWK objects through the existing static verifier boundary.
- RSA-backed tests for real ID Token verification and signing-key rotation.
- Discovery/JWKS architecture documentation and an offline executable example.

### Security

- Discovered metadata `issuer` must exactly equal the configured issuer.
- Discovery, authorization, token and JWKS URLs must use HTTPS; URI fragments are rejected.
- The configured ID Token signing algorithm must also be advertised by provider metadata.
- Remote JWKS documents reject symmetric keys and private key material.
- Only signing keys with a compatible advertised algorithm are retained.
- Remote verification requires a non-empty `kid`.
- Unknown `kid` values may trigger a bounded refresh only after the configured cooldown, limiting attacker-driven refresh amplification.
- Metadata and JWKS caches use the injected Clock and explicit TTLs.
- Discovery/JWKS network transport remains optional infrastructure and does not enter the Authentication core.

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
