# SCIM HTTP Transport — 0.4.0b5

## Purpose

Version 0.4.0b5 exposes the existing tenant-scoped provisioning core through a SCIM 2.0 HTTP protocol layer.

The architecture remains layered:

~~~text
SCIM client
    ↓
FastAPI adapter
    ↓
ScimHttpTransport
    ↓
ScimProvisioningService
    ↓
Identity / Membership / Provisioning repositories
~~~

The HTTP adapter never owns provisioning rules.

## Protocol surface

The transport exposes:

~~~text
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
~~~

## Media type

SCIM JSON responses use:

~~~text
application/scim+json
~~~

Resource responses include ETag and Location when available.

## Discovery

ServiceProviderConfig advertises only capabilities implemented in this milestone:

- PATCH: supported
- filter: supported
- ETag: supported
- bulk: unsupported
- password change: unsupported
- sorting: unsupported

The filter maximum result count is configurable.

ResourceTypes exposes only User.

Schemas exposes the supported User schema subset.

## User payload

The HTTP parser accepts the supported subset:

- userName
- externalId
- displayName
- active
- name.givenName
- name.familyName
- emails

The User schema URI must be present in schemas.

Password provisioning is rejected.

Read-only or unsupported authorization concepts do not become PyIAMKit Roles or Permissions.

## Filtering

0.4.0b5 deliberately implements a bounded filter subset:

~~~text
userName eq "..."
externalId eq "..."
~~~

Attribute names and the eq operator are parsed case-insensitively.

Other filters return a SCIM invalidFilter error.

This keeps the advertised filter capability aligned with what is actually implemented rather than pretending to support the complete SCIM filter grammar.

## Pagination

SCIM one-based pagination is preserved:

~~~text
startIndex >= 1
count >= 0
~~~

Requested count is capped by the configured ServiceProviderConfig maxResults.

## Conditional requests

PUT, PATCH and DELETE forward If-Match to the provisioning core.

A stale ETag returns HTTP 412.

Successful create/get/update responses expose the current ETag header.

## Error mapping

Transport errors are represented with:

~~~text
urn:ietf:params:scim:api:messages:2.0:Error
~~~

Mappings include:

~~~text
ProvisioningConflict            → 409 uniqueness
ProvisioningResourceNotFound    → 404
ProvisioningPreconditionFailed  → 412
UnsupportedScimPatch            → 400 invalidPath
InvalidScimRequest              → 400 invalidValue
Managed-state conflict          → 409 generic state conflict
Unexpected internal failure     → 500 generic detail
~~~

Unexpected exceptions never expose Python exception internals.

## FastAPI adapter

The optional adapter is:

~~~python
from pyiamkit.integrations.fastapi_scim import create_scim_router
~~~

It accepts a ScimHttpTransport and an explicit access dependency.

The dependency is mandatory.

PyIAMKit does not silently expose anonymous provisioning endpoints.

~~~text
request
  ↓
host-provided access dependency
  ↓
FastAPI SCIM route
  ↓
ScimHttpTransport
~~~

The host application decides whether the access mechanism is a service token, OAuth2 client credential, mTLS-derived principal, gateway identity or another enterprise control.

## Security boundaries

The following remain invariant:

- SCIM transport does not authenticate users by itself;
- an access dependency is required by the FastAPI router;
- transport does not derive Roles from SCIM groups;
- password provisioning is not accepted;
- active=false remains tenant Membership suspension;
- DELETE remains Membership revocation + SCIM tombstone;
- Identity is not globally deleted;
- externalId remains provisioning-source scoped;
- If-Match failures fail closed;
- malformed resource IDs do not leak internal parser details.

## Deferred scope

Not implemented in 0.4.0b5:

- Group resources
- complete RFC filter grammar
- sorting
- bulk operations
- password change
- attribute projection using attributes/excludedAttributes
- conditional GET / If-None-Match
- vendor-specific Entra/Okta/Auth0 provisioning profiles
- Django SCIM router

## Qualification target

The milestone must pass:

- SCIM protocol unit tests
- FastAPI SCIM end-to-end tests
- Python 3.12 / 3.13
- Ruff lint + format
- mypy strict
- global coverage >= 90%
- live PostgreSQL persistence regression
- Django 5.2 / 6.1 regression
- wheel build + installed-wheel examples
- Bandit

## Next milestone

A following 0.4.x milestone can add provider interoperability profiles:

~~~text
Microsoft Entra provisioning
Okta SCIM provisioning
Auth0 / enterprise directory integrations
SCIM Group model
provider quirks / compatibility matrix
~~~
