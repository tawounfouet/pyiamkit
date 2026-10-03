# Integration guide — PyIAMKit 0.5.0

## Integration philosophy

Framework integrations depend on PyIAMKit core contracts. Framework-native
permissions, decorators, request globals or ORM models do not become IAM authority.

The host application should keep this direction:

```text
framework request
      |
integration adapter
      |
PyIAMKit authentication / authorization
      |
authoritative repositories
```

## FastAPI

The FastAPI integration supports protected routes and SCIM HTTP transport.

Install:

```bash
python -m pip install "pyiamkit[fastapi]"
```

For bearer-token applications, combine with the JWT extra:

```bash
python -m pip install "pyiamkit[fastapi,jwt]"
```

Operationally:

- resolve an authenticated subject through the configured token/session authority;
- construct an explicit AuthorizationRequest;
- do not trust roles copied from an unverified request/header;
- keep Tenant context explicit;
- translate domain denials into framework HTTP responses at the boundary.

See the executable FastAPI examples under `examples/`.

## Django

Install:

```bash
python -m pip install "pyiamkit[django]"
```

PyIAMKit's Django integration is qualified against supported Django 5.2 and 6.1
lines.

Do not treat Django's native permission model as a substitute for PyIAMKit
Role/Permission/RoleBinding semantics unless the application explicitly builds and
qualifies a mapping layer.

## JWT

Install:

```bash
python -m pip install "pyiamkit[jwt]"
```

JWT verification validates cryptographic/trust context and then consults durable
Session state. JWT claims are not the durable source of truth for current roles or
revocation.

## OIDC

Static-key federation:

```bash
python -m pip install "pyiamkit[oidc]"
```

OIDC Discovery/JWKS:

```bash
python -m pip install "pyiamkit[oidc-http]"
```

Applications must configure expected issuer/audience and operate key rotation.
Discovery/JWKS network behavior belongs at the adapter boundary.

## SCIM

SCIM User and Group provisioning are independent from implicit RBAC assignment.

Important baseline:

- SCIM Group membership does not automatically create RoleBindings;
- provider profiles are qualified offline for Microsoft Entra and Okta;
- password provisioning remains rejected;
- top-level projection follows the implemented SCIM contract.

If an application later maps external Groups to Roles, that mapping should be
explicit, Tenant-scoped and policy controlled.

## SQLAlchemy / PostgreSQL

Install:

```bash
python -m pip install "pyiamkit[postgres]"
```

Use `migrate_schema()` for the production migration baseline. Repositories do not
commit implicitly; host applications own transaction boundaries.

## Redis

Install:

```bash
python -m pip install "pyiamkit[redis]"
```

Redis adapters are derived operational projections. They do not replace
authoritative repositories.

## SIEM

The core exports a vendor-neutral SecurityEventSink boundary and
GenericSecurityEventExporter.

Vendor-specific transports should be implemented outside domain contracts and
should preserve:

- event ID;
- event version;
- Tenant/actor/subject/correlation context;
- redaction guarantees.

## Third-party adapters

Third-party adapters should consume `pyiamkit.conformance` suites in their own CI.

At minimum select the suites matching the adapter:

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

A capability flag must never weaken a baseline security invariant.
