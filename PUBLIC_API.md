# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.1.0a2

The `0.1.0a1` Identity API remains public alpha API.

Alpha Tenancy API from `pyiamkit.tenancy`:

```text
Tenant
TenantId
TenantStatus
Membership
MembershipId
MembershipStatus
Organization
OrganizationId
TenantContext
TenantScope
TenantIsolationGuard
TenancyApplicationService
TenantRepository
MembershipRepository
TenancyError
TenantNotFound
MembershipNotFound
TenantInactive
MembershipInactive
TenantMismatch
InvalidTenant
InvalidTenantTransition
InvalidMembership
InvalidMembershipTransition
```

These contracts remain pre-1.0 alpha APIs.

## 0.1.0a1

Root-level stable-for-this-alpha symbol:

```python
pyiamkit.__version__
```

Alpha Identity API from `pyiamkit.identity`:

```text
Identity
IdentityId
IdentityType
IdentityStatus
User
ServiceAccount
EmailAddress
IdentityApplicationService
IdentityRepository
IdentityError
IdentityNotFound
InvalidIdentityTransition
InvalidDisplayName
InvalidEmailAddress
InvalidServiceAccount
InvalidExternalIdentity
ExternalIdentityAlreadyLinked
ExternalIdentityLinkNotFound
```

## 0.0.1

The initial root public API contained only `pyiamkit.__version__`.
