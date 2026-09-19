# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.4.0b8

Adds bounded SCIM representation projection:

```text
ScimAttributeSelection
parse_attribute_selection()
project_scim_resource()
```

The FastAPI SCIM adapter forwards `attributes` and `excludedAttributes` on User and Group GET/list routes.

Projection accepts only top-level attributes implemented by PyIAMKit. `schemas`, `id` and `meta` remain always returned. Unknown attributes and nested attribute paths fail closed.

The release also adds offline provider-qualification suites for Microsoft Entra and Okta. These suites exercise the public protected FastAPI SCIM router and do not bypass the normal transport or provisioning services.

Microsoft Entra qualification includes `excludedAttributes=members` Group reads and documented Group member PATCH patterns. Okta qualification includes quoted pre-create userName lookup and pathless Group PATCH rename behavior.

Qualification means deterministic local compatibility tests pass; it does not mean external vendor certification.

## 0.4.0b7

Adds the SCIM Group provisioning surface from `pyiamkit.provisioning`:

```text
SCIM_GROUP_SCHEMA
ProvisioningGroup
ProvisioningGroupRepository
ScimGroupProvisioningService
ScimGroupInput
ScimGroupMember
ScimGroupResource
ScimGroupListResponse
ScimGroupPatchOperation
parse_scim_group_payload()
parse_scim_group_patch_payload()
parse_group_filter()
```

Reference adapters:

```text
pyiamkit.provisioning.adapters.InMemoryProvisioningGroupRepository
pyiamkit.persistence.sqlalchemy.SqlAlchemyProvisioningGroupRepository
```

When `ScimHttpTransport` receives `group_service=`, it additionally exposes Group discovery and the following transport operations:

```text
POST   /Groups
GET    /Groups
GET    /Groups/{id}
PUT    /Groups/{id}
PATCH  /Groups/{id}
DELETE /Groups/{id}
```

FastAPI adds these routes only when Groups are configured. They use the same mandatory host-provided access dependency as User provisioning.

Supported Group filters are equality lookup on `displayName` and `externalId`. Supported members reference active SCIM User resource IDs from the same provisioning source and Tenant.

SCIM Group membership is intentionally independent from PyIAMKit Roles, Permissions and RoleBindings. Nested Groups and implicit Group-to-Role mapping remain outside this public milestone.

## 0.4.0b6

Adds explicit SCIM provider-interoperability contracts:

```text
GENERIC_SCIM_PROFILE
MICROSOFT_ENTRA_PROFILE
OKTA_SCIM_PROFILE
ScimDeprovisionMode
ScimProviderKind
ScimProviderProfile
ScimUserFilterExpression
scim_provider_profile()
parse_user_filter_expression()
```

`ScimHttpTransport(..., provider_profile=...)` selects protocol parsing behavior without changing provisioning or authorization semantics.

The Generic profile remains the default and preserves the strict `0.4.0b5` filter contract.

The Microsoft Entra profile allows the bounded compatibility forms implemented by this release, including unquoted single-token values and conjunctions of supported equality clauses.

The Okta profile keeps quoted string filters and prioritizes `userName` as its interoperability lookup convention.

Only `userName` and `externalId` equality clauses are supported. These profiles are compatibility presets, not Microsoft or Okta certification claims.

## 0.4.0b5

Adds the framework-neutral SCIM HTTP surface from `pyiamkit.provisioning`:

```text
SCIM_MEDIA_TYPE
SCIM_ERROR_SCHEMA
SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA
SCIM_RESOURCE_TYPE_SCHEMA
SCIM_SCHEMA_SCHEMA
ScimErrorType
ScimErrorResponse
ScimHttpResponse
ScimHttpTransport
ScimServiceProviderConfig
ScimUserFilter
parse_user_filter()
parse_scim_user_payload()
parse_scim_patch_payload()
```

The optional FastAPI adapter is imported explicitly:

```python
from pyiamkit.integrations.fastapi_scim import (
    ScimAccessDependency,
    create_scim_router,
)
```

`create_scim_router()` requires an explicit `access_dependency`; no anonymous default is provided.

Supported endpoints in this milestone:

```text
GET    /ServiceProviderConfig
GET    /ResourceTypes
GET    /ResourceTypes/User
GET    /Schemas
GET    /Schemas/{schema-uri}
POST   /Users
GET    /Users
GET    /Users/{id}
PUT    /Users/{id}
PATCH  /Users/{id}
DELETE /Users/{id}
```

The filter subset is deliberately bounded to equality lookup for `userName` and `externalId`. Full SCIM filter grammar, Groups, sorting, bulk operations and password change remain outside this public milestone.

## 0.4.0b4

Adds the framework-neutral provisioning surface from `pyiamkit.provisioning`:

```text
ProvisioningSource
ProvisioningResourceId
ProvisioningResourceStatus
ProvisioningUser
ProvisioningUserRepository
ScimProvisioningService
ScimUserInput
ScimUserResource
ScimName
ScimEmail
ScimMeta
ScimListResponse
ScimPatchOperation
ScimPatchVerb
ProvisioningConflict
ProvisioningPreconditionFailed
ProvisioningResourceNotFound
ProvisioningManagedStateConflict
UnsupportedScimPatch
```

Reference persistence:

```text
pyiamkit.provisioning.adapters.InMemoryProvisioningUserRepository
pyiamkit.persistence.sqlalchemy.SqlAlchemyProvisioningUserRepository
```

The SCIM service is transport-independent in this milestone. It manages tenant-scoped User provisioning and supports explicit User create/get/list/replace/PATCH/delete orchestration.

`externalId` is interpreted within a `ProvisioningSource`. The SCIM resource `id` is generated by PyIAMKit and remains stable/non-reassigned.

`active=false` controls the managed Tenant Membership. DELETE revokes that Membership and tombstones the SCIM resource; the global Identity is preserved.

Supported PATCH paths in this milestone are `active`, `userName`, `displayName`, `externalId`, `name.givenName`, `name.familyName` and `emails`. SCIM Groups and password provisioning remain out of scope.

## 0.4.0b3

Adds the optional synchronous Django adapter from `pyiamkit.integrations.django`:

```text
DjangoAuthenticationRequired
DjangoCorrelationIdResolver
DjangoResourceResolver
DjangoScopeResolver
DjangoTenantResolver
PyIAMKitAuthenticationMiddleware
authenticate_request()
bearer_required()
get_authenticated_claims()
get_authorization_decision()
permission_required()
```

Install it with:

```text
pyiamkit[django]
```

Supported/qualified Django lines in this milestone:

```text
Django 5.2.x
Django 6.1.x
```

`PYIAMKIT_TOKEN_PROVIDER` may be configured in Django settings as either a TokenProvider-compatible object or a dotted import path. Passing `token_provider=` directly to a decorator takes precedence and avoids global settings lookup.

The middleware performs optional authentication and attaches verified claims when a Bearer header exists. It does not make every Django route private.

The decorators are synchronous. Async views are rejected explicitly until PyIAMKit has an async-safe repository/service execution model.

Django's own User/groups/permissions/superuser flags are not treated as PyIAMKit authorization inputs.

## 0.4.0b2

Adds assurance-aware authorization contracts from `pyiamkit.authorization`:

```text
AuthenticationEvidence
MinimumAssuranceConstraint
AuthorizationReason.DENY_AUTHENTICATION_CONTEXT_MISSING
AuthorizationReason.DENY_STEP_UP_REQUIRED
AuthorizationDecision.step_up_required
AuthorizationDecision.required_assurance_level
AuthorizationDecision.required_mfa
```

Governance registration adds:

```python
governance.register_minimum_assurance(
    "payment.approve",
    minimum_assurance=AssuranceLevel.AAL2,
    require_mfa=True,
    tenant_id=tenant_id,
)
```

`AuthorizationRequest.authentication` accepts an `AuthenticationEvidence` snapshot. The Authorization Engine does not load or mutate Authentication Sessions.

The FastAPI adapter builds this evidence from verified `AccessTokenClaims`. A step-up-required decision maps to HTTP 403 with:

```json
{
  "detail": {
    "code": "step_up_required",
    "required_assurance_level": "aal2",
    "required_mfa": true
  }
}
```

Ordinary authorization denials remain the existing generic 403 response.

## 0.4.0b1

Adds MFA domain/application contracts from `pyiamkit.authentication`:

```text
MfaApplicationService
MfaFactor
MfaFactorId
MfaFactorRepository
MfaFactorStatus
MfaFactorType
MfaSecretStore
TotpEnrollment
TotpEnrollmentMaterial
TotpProvider
MfaFactorNotFound
MfaFactorOwnershipMismatch
MfaReplayDetected
MfaSecretUnavailable
MfaVerificationFailed
```

The optional PyOTP adapter is imported explicitly:

```python
from pyiamkit.authentication.adapters.totp import (
    InMemoryMfaSecretStore,
    PyOtpTotpProvider,
)
```

Install it with:

```text
pyiamkit[mfa]
```

SQLAlchemy persistence adds `SqlAlchemyMfaFactorRepository`.

`Session.step_up()` records the verified local MFA factor, the MFA verification time and the resulting assurance level. TOTP step-up is capped at AAL2.

The factor aggregate stores only a `secret_reference`. Production applications should provide a secret-store adapter backed by an appropriate vault/KMS/HSM-capable system rather than the InMemory reference store.

## 0.4.0a2

Adds optional OIDC Discovery/JWKS infrastructure from
`pyiamkit.authentication.adapters.oidc_discovery`:

```text
DiscoveredOidcIdTokenVerifier
HttpxOidcTransport
JwksKeyResolver
OidcDiscoveryClient
OidcDiscoveryError
OidcJsonTransport
OidcJwksError
OidcProviderMetadata
OidcRemoteError
```

Install it with:

```text
pyiamkit[oidc-http]
```

`OidcDiscoveryClient` resolves
`<issuer>/.well-known/openid-configuration`, requires the returned issuer to
match the configured issuer exactly and caches validated metadata.

`JwksKeyResolver` downloads and caches public signing JWKs, rejects symmetric
or private key material and supports bounded refresh when a new `kid` appears.

`DiscoveredOidcIdTokenVerifier` requires the configured algorithm to be
advertised by provider metadata, resolves the token's `kid` through the JWKS
cache and delegates all ID Token claim validation to
`StaticOidcIdTokenVerifier`.

The HTTP transport is explicit and optional. Applications can provide another
`OidcJsonTransport` implementation for proxies, service meshes or controlled
enterprise egress.

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
