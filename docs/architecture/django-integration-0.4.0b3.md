# Django Integration — 0.4.0b3

## Purpose

Version 0.4.0b3 exposes PyIAMKit Authentication and Authorization to synchronous Django views without moving Django concepts into the IAM core.

~~~text
HttpRequest
   ↓
Authorization: Bearer ...
   ↓
TokenProvider
   ↓
AccessTokenClaims
   ↓
explicit application resolvers
   ↓
AuthorizationEngine
   ↓
HttpResponse
~~~

## Supported Django lines

The release is qualified in CI against:

~~~text
Django 5.2.x
Django 6.1.x
~~~

The package extra is bounded to Django >=5.2,<6.2.

## Core boundary

The Django adapter depends inward on:

- Authentication contracts;
- Authorization contracts;
- Tenancy value objects.

Authentication, Authorization and Tenancy do not import Django.

## No implicit django.contrib.auth bridge

PyIAMKit does not automatically translate:

- request.user;
- Django groups;
- Django permissions;
- is_staff;
- is_superuser.

into PyIAMKit:

- Identity;
- Membership;
- Role;
- RoleBinding;
- Permission;
- TenantScope.

Any interoperability must be explicit and auditable.

In particular, is_superuser is not an unconditional PyIAMKit bypass.

## Authentication helper

authenticate_request(request, token_provider) reads the Authorization header and requires:

~~~text
scheme = Bearer
credential != empty
TokenProvider.verify_access_token() succeeds
~~~

Failure raises an internal DjangoAuthenticationRequired signal.

Protected decorators map this to:

~~~text
HTTP 401
WWW-Authenticate: Bearer
{"detail": "Not authenticated"}
~~~

Token-validation internals are not returned to the caller.

## Optional middleware

PyIAMKitAuthenticationMiddleware authenticates only when an Authorization header exists.

~~~text
public request without Bearer
        ↓
middleware does nothing
        ↓
view continues

request with valid Bearer
        ↓
verified claims attached
        ↓
view/decorator may reuse them

request with invalid Bearer
        ↓
authentication error recorded
        ↓
middleware does not globally block public endpoint
~~~

Endpoint protection remains explicit.

## Provider configuration

A decorator may receive token_provider directly.

If omitted, the adapter resolves:

~~~text
settings.PYIAMKIT_TOKEN_PROVIDER
~~~

The setting may be:

- a TokenProvider-compatible object;
- a dotted import path to such an object.

Missing or incompatible configuration raises ImproperlyConfigured.

## bearer_required

bearer_required protects a synchronous view with Authentication only.

It:

1. reuses middleware claims when available;
2. otherwise verifies the request Bearer token;
3. attaches verified claims to the request;
4. returns 401 on Authentication failure;
5. executes the view on success.

The view can retrieve claims through get_authenticated_claims(request).

## permission_required

permission_required composes:

~~~text
Bearer authentication
       ↓
TenantResolver
       ↓
ScopeResolver or TenantScope
       ↓
optional ResourceResolver
       ↓
AuthenticationEvidence
       ↓
AuthorizationRequest
       ↓
AuthorizationEngine
~~~

The final AuthorizationDecision is attached to the request and can be retrieved with get_authorization_decision(request).

## Tenant boundary

No default header-based Tenant resolver is provided.

The host application must explicitly define how a request maps to a Tenant.

This prevents an arbitrary client-controlled tenant header from becoming trusted IAM context.

## Assurance / step-up

Verified access-token claims provide:

~~~text
assurance_level
mfa
auth_time
~~~

These become AuthenticationEvidence for Authorization.

Ordinary deny:

~~~json
{"detail": "Forbidden"}
~~~

Step-up-required deny:

~~~json
{
  "detail": {
    "code": "step_up_required",
    "required_assurance_level": "aal2",
    "required_mfa": true
  }
}
~~~

Both are HTTP 403 because authentication already succeeded.

## Request attributes

The adapter uses private-ish namespaced request attributes:

~~~text
request.pyiamkit_claims
request.pyiamkit_authentication_error
request.pyiamkit_authorization_decision
~~~

Consumers should prefer the provided getter helpers instead of trusting arbitrary request attributes directly.

## Sync-first design

The current repositories and application services are synchronous.

Therefore this milestone explicitly rejects coroutine views.

It does not wrap synchronous IAM calls inside async views because that would hide blocking behavior and can conflict with Django's async-safety protections.

Future async support should begin with async-safe PyIAMKit repository/application ports.

## Security properties

- no Django superuser bypass;
- no automatic Django-group-to-Role mapping;
- no automatic Tenant inference from client headers;
- no direct JWT decoding in Django integration;
- no duplicate RBAC evaluation;
- generic 401 Authentication response;
- generic 403 ordinary Authorization response;
- structured 403 only for actionable step-up;
- public endpoints remain public unless protected explicitly;
- async unsupported modes fail explicitly.

## Testing

The integration suite covers:

- missing Bearer -> 401;
- valid Bearer claims attachment;
- optional middleware behavior;
- AAL2+MFA permission allow;
- AAL1 step-up-required 403;
- ordinary deny 403;
- settings-based token provider;
- missing configuration error;
- async-view rejection.

A dedicated compatibility matrix runs the same tests on Django 5.2.x and 6.1.x.

## Non-goals

This milestone does not provide:

- Django ORM repositories for PyIAMKit;
- Django user model synchronization;
- Django admin UI;
- Django permission backend integration;
- session-cookie authentication;
- CSRF policy;
- async IAM execution;
- DRF authentication classes.

Those can be added as explicit adapters without changing the IAM domains.
