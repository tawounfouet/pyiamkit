# Adapter Contract Matrix — 1.0.0rc1

## Principle

Adapters depend inward on framework-neutral PyIAMKit contracts. They do not redefine
IAM authority.

The public adapter surface is frozen alongside core contracts.

## Reference adapters

| Area | Public import | Qualification |
| --- | --- | --- |
| Identity memory | `pyiamkit.identity.adapters.memory` | RepositoryConformance + unit |
| Tenancy memory | `pyiamkit.tenancy.adapters` | CI + Tenant isolation scenarios |
| Authorization memory | `pyiamkit.authorization.adapters` | Authorization/Policy/Tenant conformance |
| Authentication memory | `pyiamkit.authentication.adapters` | AuthenticationConformance |
| Audit memory | `pyiamkit.audit.adapters` | Event/repository tests |
| Provisioning memory | `pyiamkit.provisioning.adapters` | SCIM/provider qualification |
| Distributed memory | `pyiamkit.operations.adapters` | operations conformance/security |
| SQLAlchemy bundle | `pyiamkit.persistence.sqlalchemy` | RepositoryConformance + SQLite/PostgreSQL |
| JWT | `pyiamkit.authentication.adapters.jwt` | TokenProviderConformance + security |
| OIDC static | `pyiamkit.authentication.adapters.oidc` | OIDC/security qualification |
| OIDC Discovery/JWKS | `pyiamkit.authentication.adapters.oidc_discovery` | OIDC/key-rotation qualification |
| TOTP | `pyiamkit.authentication.adapters.totp` | MFA/SecretStore qualification |
| Redis | `pyiamkit.operations.adapters.redis` | live Redis 7 qualification |
| FastAPI | `pyiamkit.integrations.fastapi` | integration tests |
| FastAPI SCIM | `pyiamkit.integrations.fastapi_scim` | SCIM/provider qualification |
| Django | `pyiamkit.integrations.django` | Django 5.2 / 6.1 integration |

## Reusable conformance contracts

Third-party adapters should select the applicable suites from
`pyiamkit.conformance`:

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

A conformance pass validates the named PyIAMKit contract only. It is not external
vendor certification and does not replace security/production qualification.

## Adapter compatibility rule

A 1.x adapter may add optional capability, but it must not weaken baseline security
semantics.

Examples of forbidden compatibility shortcuts:

- treating Redis as authorization authority;
- trusting JWT Roles/Permissions as durable authority;
- bypassing Tenant isolation;
- mapping SCIM Groups to Roles implicitly;
- making missing security infrastructure an implicit ALLOW;
- committing caller-owned SQLAlchemy transactions internally.

## Optional dependency rule

Core PyIAMKit remains framework-agnostic.

Optional adapters may depend on their required external libraries, but core/domain
packages must not acquire those dependencies merely to simplify adapter code.
