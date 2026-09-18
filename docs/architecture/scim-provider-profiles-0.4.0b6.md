# SCIM Provider Interoperability Profiles — 0.4.0b6

## Purpose

Version 0.4.0b6 adds explicit interoperability profiles for SCIM clients without introducing vendor SDKs or vendor authorization semantics into the PyIAMKit core.

The model stays layered:

~~~text
SCIM client family
(Generic / Microsoft Entra / Okta)
        ↓
ScimProviderProfile
        ↓
ScimHttpTransport
        ↓
ScimProvisioningService
        ↓
Identity / Membership / Provisioning
~~~

Profiles affect protocol compatibility only. They never grant Roles, Permissions or bypass tenant-scoped lifecycle rules.

## Why profiles exist

SCIM 2.0 defines the protocol, but real provisioning clients may use slightly different request patterns.

PyIAMKit therefore separates:

~~~text
normative SCIM behavior
        +
explicit provider interoperability hints
        =
predictable transport behavior
~~~

This is preferable to scattering vendor-name conditionals throughout HTTP parsing.

## Profiles

### Generic SCIM

~~~text
kind: generic
quoted filter values: required
logical AND: disabled
preferred lookup: userName, externalId
default page size: 100
deprovision: active=false
groups: unsupported
~~~

This remains the strict default and preserves the 0.4.0b5 contract.

### Microsoft Entra

~~~text
kind: microsoft_entra
unquoted filter values: accepted
logical AND: accepted
preferred lookup: externalId, userName
default page size: 100
deprovision: active=false
groups: unsupported
~~~

The profile accommodates Entra-style lookup examples such as:

~~~text
externalId eq ext-42
~~~

and bounded conjunctions such as:

~~~text
userName eq "alice@example.com" and externalId eq ext-42
~~~

Only the attributes already supported by PyIAMKit are accepted.

### Okta

~~~text
kind: okta
quoted filter values: required
logical AND: disabled
preferred lookup: userName
default page size: 100
deprovision: active=false
groups: unsupported
~~~

This matches the common Okta pre-create existence-check pattern:

~~~text
userName eq "alice@example.com"
~~~

## Filter expression model

0.4.0b6 adds:

~~~text
ScimUserFilterExpression
└── clauses: tuple[ScimUserFilter, ...]
~~~

The transport still supports only equality comparisons on:

~~~text
userName
externalId
~~~

A provider profile may allow several clauses joined by AND, but no OR, NOT, relational comparison, array filter or arbitrary attribute lookup is introduced.

## Parsing safety

The AND splitter is quote-aware.

The token:

~~~text
"Research and Development"
~~~

is one string literal and is not split at the word "and".

Malformed quotes fail closed as an invalid SCIM filter.

Unquoted values are accepted only when the active provider profile explicitly allows them.

## Candidate resolution

For a multi-clause filter:

1. resolve the first supported clause through the existing indexed provisioning lookup;
2. retrieve at most one candidate;
3. evaluate all remaining clauses against that candidate;
4. return either one match or zero matches.

The profile never broadens the supported business object set.

## Provider profile model

~~~text
ScimProviderProfile
├── kind
├── allow_unquoted_filter_values
├── allow_and_filters
├── preferred_user_lookup_attributes
├── default_page_size
├── deprovision_mode
└── supports_groups
~~~

The current deprovision mode is intentionally:

~~~text
ACTIVE_FALSE
~~~

which maps to the existing tenant-scoped Membership suspension semantics.

## Security invariants

Provider profiles MUST NOT change:

- tenant isolation;
- Identity vs Membership lifecycle separation;
- source-scoped externalId;
- stable/non-reassigned SCIM resource id;
- password-provisioning rejection;
- If-Match behavior;
- tombstone semantics;
- no implicit Group → Role mapping;
- no external claim → Permission mapping;
- fail-closed malformed filters.

## No vendor SDK dependency

The provider profiles are plain immutable Python values.

No Microsoft, Okta or other vendor SDK is imported into:

- domain;
- application;
- provisioning core;
- SCIM HTTP transport.

The framework remains deployable behind gateways, service meshes and enterprise network controls without provider lock-in.

## Not a certification claim

These profiles are interoperability presets, not certification.

In particular, the Microsoft Entra profile is not a claim of Microsoft Entra App Gallery readiness. Group provisioning is still unsupported in this milestone.

Likewise, the Okta profile is not a claim of Okta Integration Network certification.

Provider certification requires additional external validation beyond unit/integration compatibility tests.

## Qualification

0.4.0b6 qualifies:

- strict Generic profile remains backward-compatible;
- Entra unquoted externalId lookup;
- Entra bounded AND filter;
- quote-aware AND parsing;
- Okta quoted userName lookup;
- provider-specific rejection of unsupported syntax;
- no provider profile leakage into another profile;
- Python 3.12 / 3.13;
- Ruff;
- mypy strict;
- coverage >= 90%;
- PostgreSQL regression;
- Django 5.2 / 6.1 regression;
- FastAPI SCIM regression;
- wheel and examples;
- Bandit.

## Next milestones

Potential next steps include:

~~~text
SCIM Groups
explicit external Group → internal Group/Role mapping policies
Microsoft Entra interoperability test harness
Okta interoperability test harness
provider-specific compatibility matrices
bulk / sorting / broader filters only when required
~~~

Any Group-to-Role capability should remain an explicit provisioning policy, never an implicit name-based authorization shortcut.
