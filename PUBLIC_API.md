# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.4.0a1

Adds framework-neutral federation contracts from `pyiamkit.authentication`:

```text
ExternalIdentityNotLinked
FederatedAssurance
FederatedAssuranceResolver
FederatedAuthenticationService
FederatedIdentityClaims
FederationError
IdentityTokenVerifier
InvalidFederationPolicy
InvalidIdentityToken
```

The optional OIDC adapter is imported explicitly:

```python
from pyiamkit.authentication.adapters.oidc import (
    OidcConfigurationError,
    StaticOidcAssuranceResolver,
    StaticOidcIdTokenVerifier,
)
```

Install it with:

```text
pyiamkit[oidc]
```

`StaticOidcIdTokenVerifier` verifies an OIDC ID Token against a configured provider ID, exact issuer, client ID, signing algorithm and one or more verification keys. It supports expected nonce verification, `kid` key selection and OIDC authorized-party validation.

`FederatedAuthenticationService` resolves the verified external subject through the existing `IdentityRepository.find_by_external_subject(provider_id, subject)` contract and then opens a local OIDC Session through `AuthenticationApplicationService`.

Email claims are informational only. The service never links an external identity by email and does not auto-provision Roles, Permissions or Memberships.

This milestone intentionally uses configured verification keys. OIDC Discovery/JWKS retrieval and vendor-specific provider integrations remain separate infrastructure work.

## 0.3.0b2

Adds the optional FastAPI adapter from `pyiamkit.integrations.fastapi`:

```text
AuthenticationDependency
CorrelationIdResolver
ResourceResolver
ScopeResolver
TenantResolver
bearer_authentication()
require_permission()
```

Install it with:

```text
pyiamkit[fastapi]
```

JWT-backed FastAPI applications normally install both optional adapters:

```text
pyiamkit[jwt,fastapi]
```

`bearer_authentication()` returns a FastAPI dependency that reads the HTTP Bearer credential and delegates verification to a supplied `TokenProvider`. Token-provider details are never returned to the client; authentication failure maps to HTTP 401 with `WWW-Authenticate: Bearer`.

`require_permission()` consumes verified `AccessTokenClaims`, resolves the application-specific Tenant/Scope/Resource context, builds an `AuthorizationRequest` and delegates the final decision to `AuthorizationEngine`. A denied decision maps to HTTP 403.

Tenant resolution is deliberately not inferred from arbitrary headers by PyIAMKit. The host application supplies a `TenantResolver` suitable for its routing/session model.

## 0.3.0b1

Adds framework-neutral token contracts from `pyiamkit.authentication`:

```text
AccessTokenClaims
ExpiredAccessToken
InvalidAccessToken
IssuedAccessToken
TokenConfigurationError
TokenError
TokenId
TokenProvider
TokenSessionInactive
TokenType
```

The optional PyJWT adapter is imported explicitly:

```python
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
```

Install it with:

```text
pyiamkit[jwt]
```

`JwtTokenProvider` issues access JWTs from an existing active `Session` and verifies both the cryptographic token and the current durable Session state. A valid signature does not override Session revocation or expiration.

The access-token payload intentionally excludes Roles and Permissions. Authorization continues to resolve current RoleBindings, policies, constraints and SoD rules from PyIAMKit's authorization model.

The configured algorithm, issuer and audience are trusted configuration. The token header never selects the allowed algorithm. Optional `kid` lookup supports verification-key rotation.

Refresh tokens are not part of the `0.3.0b1` public API.

## 0.3.0a2

Adds the framework-neutral Authentication bounded context from `pyiamkit.authentication`:

```text
AssuranceLevel
AuthenticationApplicationService
AuthenticationContext
AuthenticationError
AuthenticationMethod
AuthenticationSubjectInactive
Credential
CredentialAlreadyExists
CredentialId
CredentialNotFound
CredentialRepository
CredentialStatus
CredentialType
InvalidCredential
InvalidCredentialTransition
InvalidSession
InvalidSessionTransition
Session
SessionId
SessionNotFound
SessionRepository
SessionStatus
```

Reference InMemory adapters are available from `pyiamkit.authentication.adapters`:

```text
InMemoryCredentialRepository
InMemorySessionRepository
```

Optional SQLAlchemy persistence adds:

```text
SqlAlchemyCredentialRepository
SqlAlchemySessionRepository
```

`Credential.reference` is an opaque pointer to externally protected secret material. It is not the password, API key, client secret or other raw credential. PyIAMKit does not expose an API for storing raw authentication secrets in the Credential aggregate.

`AuthenticationContext` records how authentication was established and the resulting assurance level independently of token format. JWT issuance/verification remains deferred to `0.3.0b1`.

Session and Credential repositories preserve caller-owned transaction semantics and never commit the host application's SQLAlchemy transaction.

## 0.3.0a1

Adds optional SQLAlchemy persistence adapters from `pyiamkit.persistence.sqlalchemy`:

```text
SqlAlchemyAuditRepository
SqlAlchemyConstraintRepository
SqlAlchemyIdentityRepository
SqlAlchemyMembershipRepository
SqlAlchemyPermissionCatalogRepository
SqlAlchemyRoleBindingRepository
SqlAlchemyRoleRepository
SqlAlchemySoDRuleRepository
SqlAlchemyTenantRepository
create_schema()
create_session_factory()
create_sqlalchemy_engine()
drop_schema()
```

Installation extras:

```text
pyiamkit[sqlalchemy]  # SQLAlchemy adapter, SQLite-compatible
pyiamkit[postgres]    # SQLAlchemy + psycopg for PostgreSQL
```

The existing domain repository protocols are unchanged. SQLAlchemy adapters receive an existing `Session`, execute persistence operations and deliberately do not commit. Transaction ownership stays with the host application.

`create_schema()` is an alpha bootstrap/test helper, not a substitute for a production migration workflow. PostgreSQL compatibility is qualified in CI against a live PostgreSQL 16 service.

## 0.2.0b2

Adds the append-only audit bounded context from `pyiamkit.audit`:

```text
AuditCategory
AuditEvent
AuditEventId
AuditOutcome
AuditRepository
AuditSink
DomainEventAuditBridge
```

Adds authorization audit and explanation contracts from `pyiamkit.authorization`:

```text
AuthorizationDecisionAuditRecorder
AuthorizationDecisionId
DecisionExplanation
ExplanationLevel
```

`AuthorizationEngine` accepts an optional `audit_sink` and adds:

```text
AuthorizationEngine.describe()
```

The existing `AuthorizationEngine.explain()` contract is preserved. `AuthorizationDecision.explanation()` projects either a safe summary or opt-in detailed internal path.

Authorization audit records deliberately omit resource attribute payloads. A configured audit sink participates synchronously in decision finalization; write failures are not silently ignored.

## 0.2.0b1

Adds restrictive authorization-governance contracts from `pyiamkit.authorization`:

```text
AccessGovernanceApplicationService
AuthorizationConstraint
ConstraintEvaluator
ConstraintRepository
DistinctActorSoDRule
DynamicSoDEvaluator
GovernanceRuleId
GovernanceViolation
GovernanceViolationKind
MutuallyExclusiveRolesRule
NumericMaximumConstraint
ResourceAttributeEqualsConstraint
ResourceDescriptor
SeparationOfDutyRule
SoDRuleRepository
StaticSoDEvaluator
StaticSoDViolation
```

`AuthorizationRequest` may carry a tenant-bound `ResourceDescriptor`, and `AuthorizationDecision` may expose `matched_rule_id` for restrictive governance provenance.

Governance rules are deny-only: they can reduce a candidate RBAC authorization to `DENY` but cannot create an `ALLOW`.

## 0.2.0a2

Adds hierarchical RBAC contracts from `pyiamkit.authorization`:

```text
RoleHierarchyApplicationService
RoleHierarchyResolver
RoleHierarchyError
RoleHierarchyCycle
RoleHierarchyDepthExceeded
RoleHierarchyTenantMismatch
RoleHierarchyUnavailable
```

`Role` exposes `parent_role_ids`, and authorization decisions distinguish:

```text
bound_role_id   # Role referenced by the effective RoleBinding
matched_role_id # Role that actually contributes the matching Permission
```

## 0.2.0a1

Adds the first runtime authorization API from `pyiamkit.authorization`:

```text
AuthorizationDecision
AuthorizationDenied
AuthorizationEngine
AuthorizationReason
AuthorizationRequest
AuthorizationResult
```

Runtime methods:

```text
AuthorizationEngine.authorize()
AuthorizationEngine.can()
AuthorizationEngine.require()
AuthorizationEngine.explain()
```

## 0.1.0b2

Adds scoped role-assignment contracts from `pyiamkit.authorization`:

```text
RoleBinding
RoleBindingId
RoleBindingStatus
GrantSource
RoleBindingApplicationService
RoleBindingRepository
InvalidRoleBinding
InvalidRoleBindingTransition
RoleBindingNotFound
RoleBindingAlreadyExists
RoleNotAssignable
RoleTenantMismatch
```

## 0.1.0b1

Beta Roles and Permissions API is available from `pyiamkit.authorization`.

## 0.1.0a2

Alpha Tenancy API is available from `pyiamkit.tenancy`.

## 0.1.0a1

Alpha Identity API is available from `pyiamkit.identity`.
