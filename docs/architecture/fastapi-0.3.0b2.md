# FastAPI Integration — 0.3.0b2

## Purpose

`0.3.0b2` exposes PyIAMKit Authentication and Authorization as optional FastAPI dependencies while keeping FastAPI outside the core domains.

The adapter is intentionally thin:

```text
HTTP request
   ↓
FastAPI HTTPBearer
   ↓
TokenProvider
   ↓
AccessTokenClaims
   ↓
application context resolvers
   ↓
AuthorizationEngine
   ↓
HTTP endpoint / HTTPException
```

It does not implement token cryptography, RBAC, tenancy or policy evaluation itself.

## Installation

```bash
python -m pip install "pyiamkit[fastapi]"
```

With the official JWT adapter:

```bash
python -m pip install "pyiamkit[jwt,fastapi]"
```

FastAPI remains optional. Importing the PyIAMKit core does not import FastAPI.

## Authentication dependency

`bearer_authentication(token_provider)` returns a FastAPI dependency.

Its responsibilities are limited to:

1. declare an HTTP Bearer security scheme;
2. read the Authorization credential;
3. require the Bearer scheme;
4. delegate token verification to `TokenProvider`;
5. return trusted `AccessTokenClaims`;
6. map authentication failure to a generic HTTP 401.

```text
missing Authorization header
        ↓
401 Not authenticated
WWW-Authenticate: Bearer

invalid / expired / revoked token
        ↓
TokenProvider rejects token
        ↓
401 Not authenticated
WWW-Authenticate: Bearer
```

Token-validation details are not copied into the HTTP response.

## Authorization dependency

`require_permission(...)` creates a second dependency around the existing default-deny `AuthorizationEngine`.

Inputs:

```text
authentication dependency
AuthorizationEngine
PermissionCode
TenantResolver
optional ScopeResolver
optional ResourceResolver
optional CorrelationIdResolver
```

Runtime:

```text
AccessTokenClaims.subject_id
        +
TenantResolver(request, claims)
        +
PermissionCode
        +
ScopeResolver or TenantScope(tenant)
        +
optional ResourceDescriptor
        ↓
AuthorizationRequest
        ↓
AuthorizationEngine.authorize()
        ↓
ALLOW → AuthorizationDecision
DENY  → HTTP 403 Forbidden
```

## 401 vs 403

The integration preserves the semantic distinction:

| State | HTTP |
|---|---:|
| Bearer credential missing | 401 |
| Bearer credential malformed | 401 |
| Access JWT invalid | 401 |
| Session revoked/expired | 401 |
| Token valid but Membership missing | 403 |
| Token valid but permission denied | 403 |
| Token valid but scope mismatch | 403 |
| Token valid but SoD/constraint denies | 403 |

401 responses contain `WWW-Authenticate: Bearer`.

403 responses do not pretend that the caller is unauthenticated.

## Tenant resolution

PyIAMKit does not provide a default HTTP-header tenant resolver.

The host application must implement:

```python
def resolve_tenant(request: Request, claims: AccessTokenClaims) -> TenantId: ...
```

This is deliberate because applications identify their active tenant differently:

- route segment;
- trusted application session;
- validated subdomain;
- gateway-injected signed context;
- user-selected tenant;
- service-specific mapping.

Reading an arbitrary client header and treating it as a trusted security boundary would be unsafe as a framework default.

After resolution, the Authorization Engine still validates Tenant status and active Membership.

## Scope resolution

Without a custom `ScopeResolver`, the adapter uses:

```python
TenantScope(tenant_id)
```

Applications that later support organization/project/resource scopes can supply a resolver without changing authentication or the Authorization Engine.

## Resource context

A `ResourceResolver` can attach a `ResourceDescriptor` to the authorization request.

This enables existing:

- ownership rules;
- numeric constraints;
- dynamic SoD;
- resource-attribute policies.

The adapter does not inspect resource attributes itself.

## Correlation IDs

By default the adapter copies `X-Request-ID` into `AuthorizationRequest.correlation_id` when present.

Applications can supply a dedicated `CorrelationIdResolver`, for example when a trusted tracing middleware already owns request correlation.

Correlation IDs are observability metadata, not authentication evidence.

## OpenAPI

The adapter uses FastAPI's native `HTTPBearer` security utility.

This means protected paths participate in the generated OpenAPI security schema and interactive documentation without a custom OpenAPI patch.

Default scheme name:

```text
PyIAMKitBearer
```

Default bearer format:

```text
JWT
```

The token implementation itself still comes from the injected `TokenProvider`.

## Dependency graph

```text
FastAPI
   ↓
pyiamkit.integrations.fastapi
   ├── pyiamkit.authentication contracts
   ├── pyiamkit.authorization contracts
   └── pyiamkit.tenancy value objects

core Authentication / Authorization
   ✗ do not import FastAPI
```

This keeps dependency direction inward.

## Security properties

The adapter guarantees:

- no direct JWT decoding in FastAPI integration;
- no duplicated authorization logic;
- generic authentication errors;
- default-deny authorization preserved;
- immediate Session-revocation effect when using the session-aware JWT provider;
- explicit tenant-context boundary;
- no internal authorization explanation path leaked in the default 403 response.

Applications may expose richer administrative diagnostics separately, subject to their own authorization checks.

## Testing

The integration suite exercises the complete path:

```text
Identity
  ↓
Tenant + Membership
  ↓
Role + Permission + RoleBinding
  ↓
Session
  ↓
JWT access token
  ↓
FastAPI HTTPBearer
  ↓
TokenProvider
  ↓
AuthorizationEngine
  ↓
200 / 401 / 403
```

It also validates the generated OpenAPI bearer scheme and custom Scope/Resource/correlation resolvers.

## Non-goals

`0.3.0b2` does not implement:

- login/password endpoints;
- token issuance HTTP endpoints;
- OAuth2 authorization server flows;
- refresh-token endpoints;
- tenant discovery from untrusted headers;
- CORS policy;
- CSRF policy;
- cookie sessions;
- application-specific exception pages;
- rate limiting.

Those remain host-application or later integration concerns.

## Next direction

With durable Authentication, JWT and FastAPI adapters available, the next major line can move into the `0.4.x` identity-integration work: OAuth2/OIDC federation, external identity providers and MFA without changing the existing authorization core.
