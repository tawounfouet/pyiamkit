"""Event names emitted by the Tenancy bounded context."""

from enum import StrEnum


class TenancyEventType(StrEnum):
    TENANT_CREATED = "TenantCreated"
    TENANT_ACTIVATED = "TenantActivated"
    TENANT_SUSPENDED = "TenantSuspended"
    TENANT_REACTIVATED = "TenantReactivated"
    TENANT_DISABLED = "TenantDisabled"
    TENANT_ARCHIVED = "TenantArchived"
    MEMBERSHIP_CREATED = "MembershipCreated"
    MEMBERSHIP_ACTIVATED = "MembershipActivated"
    MEMBERSHIP_SUSPENDED = "MembershipSuspended"
    MEMBERSHIP_REACTIVATED = "MembershipReactivated"
    MEMBERSHIP_EXPIRED = "MembershipExpired"
    MEMBERSHIP_REVOKED = "MembershipRevoked"
