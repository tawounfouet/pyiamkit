# SCIM Group Provisioning — 0.4.0b7

## Purpose

Version 0.4.0b7 adds SCIM 2.0 Group provisioning while preserving PyIAMKit's authorization boundaries.

~~~text
SCIM client
    ↓
/Groups HTTP transport
    ↓
ScimGroupProvisioningService
    ↓
ProvisioningGroup
    ↓
ProvisioningUser resource references
~~~

A SCIM Group is a provisioning resource. It is not a PyIAMKit Role and does not create a RoleBinding.

## Domain model

~~~text
ProvisioningGroup
├── id
├── source_id
├── tenant_id
├── display_name
├── external_id
├── member_ids[]
├── status
├── version / ETag
├── created_at
├── updated_at
└── deleted_at
~~~

Members are service-provider-generated SCIM User resource IDs.

Nested Groups are not supported in this milestone.

## Membership invariants

Every member must resolve to an active ProvisioningUser with the same:

~~~text
source_id
tenant_id
~~~

Therefore an external provider cannot attach:

- an arbitrary UUID;
- a User from another provisioning source;
- a User from another Tenant;
- a deleted/tombstoned User;
- a Group resource as a nested member.

Group membership changes do not modify Identity status, Tenant Membership status, Roles, Permissions or RoleBindings.

## SCIM representation

The core Group schema URI is:

~~~text
urn:ietf:params:scim:schemas:core:2.0:Group
~~~

Supported attributes:

~~~text
displayName   required
externalId    optional
members       optional multi-valued
members.value required when a member is supplied
members.$ref  rendered by PyIAMKit
members.display rendered from managed User userName
~~~

Provider-specific schema extensions may be present in an inbound payload but are not treated as authorization input.

## HTTP surface

When a Group service is configured:

~~~text
POST   /Groups
GET    /Groups
GET    /Groups/{id}
PUT    /Groups/{id}
PATCH  /Groups/{id}
DELETE /Groups/{id}
~~~

Discovery then advertises both User and Group through:

~~~text
/ResourceTypes
/Schemas
~~~

When Group provisioning is not configured, Group routes are not added by the FastAPI router and discovery continues to expose User only.

## Filters

0.4.0b7 supports:

~~~text
displayName eq "..."
externalId eq "..."
~~~

Provider profiles may permit unquoted values when already qualified by the provider profile layer.

Full Group filter grammar is not introduced.

## PATCH

Supported Group PATCH shapes include:

~~~text
replace displayName
replace/remove externalId
add members
replace members
remove members
remove members[value eq "..."]
pathless replace object
~~~

The pathless replace form supports clients such as Okta that send a value object containing displayName and/or members.

Adding an existing member is idempotent.

Removing a member not present is idempotent.

## DELETE

DELETE tombstones the Group and clears its stored membership set.

It does not:

- delete Users;
- disable Identities;
- suspend Tenant Memberships;
- revoke Roles;
- delete external source accounts.

## Concurrency

Group resources use the same weak ETag pattern as User provisioning resources.

~~~text
W/"{resource-id}-{version}"
~~~

PUT, PATCH and DELETE support If-Match.

A stale If-Match fails closed.

## Persistence

SQLAlchemy adds:

~~~text
iam_provisioning_groups
iam_provisioning_group_members
~~~

The member table references:

~~~text
iam_provisioning_groups.id
iam_provisioning_users.id
~~~

No authorization tables are referenced.

Adapters preserve caller-owned transaction boundaries.

## Provider profiles

Generic SCIM, Microsoft Entra and Okta profiles are now marked Group-capable.

This means the protocol patterns implemented by PyIAMKit are qualified for those client families. It is not a vendor certification claim.

Microsoft Entra App Gallery and Okta OIN certification require external validation beyond this repository's automated conformance suite.

## Security invariants

- Group != Role.
- Group membership != Permission.
- Group membership != RoleBinding.
- Group member IDs must resolve inside the same source and Tenant.
- Nested groups are denied in this milestone.
- Password provisioning remains unsupported.
- Provider extension attributes never become authorization truth automatically.
- Deleted Groups are immutable/tombstoned.
- Group DELETE preserves User and Membership state.

## Qualification

0.4.0b7 must pass:

- Group domain/application unit tests;
- Group HTTP tests;
- FastAPI Group end-to-end tests;
- SQLite repository conformance;
- live PostgreSQL persistence;
- Generic/Entra/Okta provider profile regression;
- Python 3.12 and 3.13;
- Ruff lint + format;
- mypy strict;
- global coverage >= 90%;
- Django regression;
- wheel install + examples;
- Bandit.

## Next direction

The next 0.4.x work should focus on provider qualification rather than automatically binding external groups to Roles.

A future Group-to-Role feature should use explicit mapping policy such as:

~~~text
ExternalGroupMapping
external_group_id
→ explicit target Role
→ explicit Tenant/Scope
→ approval / SoD policy
~~~

Name equality alone must never grant authorization.
