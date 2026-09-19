# SCIM Provider Qualification — 0.4.0b8

## Purpose

Version 0.4.0b8 turns the existing provider profiles into repeatable offline qualification scenarios.

The milestone does not add Microsoft or Okta SDK dependencies and does not claim external vendor certification.

~~~text
Provider behavior documented publicly
              ↓
offline qualification scenario
              ↓
FastAPI SCIM adapter
              ↓
ScimHttpTransport
              ↓
User / Group provisioning core
~~~

## Qualification vs certification

PyIAMKit uses the following terminology:

- **profile**: immutable interoperability parsing/configuration preset;
- **offline-qualified**: a deterministic local scenario modeled on documented provider request patterns passes in CI;
- **certified**: an external vendor program has validated the integration.

0.4.0b8 provides offline qualification only.

## Microsoft Entra scenario

The Entra qualification harness covers:

1. protected SCIM discovery;
2. User creation;
3. User lookup by unquoted externalId;
4. Group creation with User membership;
5. Group GET with excludedAttributes=members;
6. Group lookup with displayName filter and excludedAttributes=members;
7. PATCH add Group member;
8. PATCH remove Group member through members[value eq "..."];
9. User deactivation through active=false.

The scenario runs entirely in-process and does not contact Microsoft services.

## Okta scenario

The Okta qualification harness covers:

1. pre-create existence lookup with quoted userName equality;
2. User creation;
3. repeated userName lookup;
4. Group creation;
5. pathless PATCH replace for Group displayName;
6. PATCH add Group member;
7. PATCH remove Group member;
8. User deactivation through active=false.

The scenario runs entirely in-process and does not contact Okta services.

## Attribute projection

0.4.0b8 adds bounded top-level attribute projection.

Supported query parameters:

~~~text
attributes
excludedAttributes
~~~

The projection contract is intentionally conservative:

- only top-level attributes implemented by PyIAMKit are accepted;
- attribute names are parsed case-insensitively;
- duplicate names are collapsed;
- unknown attributes fail closed with InvalidScimRequest;
- nested paths and value filters are rejected;
- schemas, id and meta remain always returned by PyIAMKit.

Supported User projection attributes:

~~~text
userName
externalId
displayName
active
name
emails
~~~

Supported Group projection attributes:

~~~text
displayName
externalId
members
~~~

This is sufficient for Entra's common excludedAttributes=members Group reads without pretending to implement arbitrary SCIM attribute-path projection.

## Framework boundary

Projection belongs to the HTTP representation layer.

It does not mutate:

- ProvisioningUser;
- ProvisioningGroup;
- Identity;
- Tenant Membership;
- Role;
- Permission;
- RoleBinding.

The canonical resource remains complete inside the application/domain layers.

## FastAPI mapping

The FastAPI SCIM router forwards:

~~~text
attributes
excludedAttributes
~~~

for both User and Group GET/list routes.

The router still requires the explicit host-provided access dependency introduced in 0.4.0b5.

## Security invariants

Provider qualification does not weaken:

- source and Tenant isolation;
- ETag / If-Match concurrency;
- tombstone lifecycle;
- password-provisioning rejection;
- no implicit Group → Role mapping;
- no external group/claim → Permission mapping;
- no nested Group support;
- generic internal-error responses;
- mandatory SCIM route protection.

Projection can only remove fields from an outbound representation or select supported fields. It cannot create authorization data.

## CI gates

0.4.0b8 adds two visible gates:

~~~text
scim-entra-qualification
scim-okta-qualification
~~~

They run separately from:

- generic quality 3.12/3.13;
- PostgreSQL conformance;
- FastAPI SCIM conformance;
- SCIM Group conformance;
- provider-profile conformance;
- Django conformance;
- Bandit.

## Non-goals

This release does not provide:

- Microsoft Entra App Gallery certification;
- Okta Integration Network certification;
- real provider credentials or live-network tests;
- nested Groups;
- automatic external Group → Role mapping;
- bulk SCIM;
- arbitrary attribute path projection;
- complete SCIM filter grammar.

## Next direction

After provider qualification, the remaining 0.4.x work can focus on explicit, policy-controlled external Group mapping if desired.

A production-hardening phase can then move into 0.5.x without coupling provisioning groups directly to RBAC.
