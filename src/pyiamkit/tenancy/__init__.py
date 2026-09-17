"""Public alpha API for the Tenancy bounded context."""

from .application import TenancyApplicationService
from .domain.context import TenantIsolationGuard
from .domain.errors import (
    InvalidMembership,
    InvalidMembershipTransition,
    InvalidTenant,
    InvalidTenantTransition,
    MembershipInactive,
    MembershipNotFound,
    TenancyError,
    TenantInactive,
    TenantMismatch,
    TenantNotFound,
)
from .domain.membership import Membership
from .domain.organization import Organization
from .domain.tenant import Tenant
from .domain.value_objects import (
    MembershipId,
    MembershipStatus,
    OrganizationId,
    TenantContext,
    TenantId,
    TenantScope,
    TenantStatus,
)
from .ports import MembershipRepository, TenantRepository

__all__ = [
    "InvalidMembership",
    "InvalidMembershipTransition",
    "InvalidTenant",
    "InvalidTenantTransition",
    "Membership",
    "MembershipId",
    "MembershipInactive",
    "MembershipNotFound",
    "MembershipRepository",
    "MembershipStatus",
    "Organization",
    "OrganizationId",
    "TenancyApplicationService",
    "TenancyError",
    "Tenant",
    "TenantContext",
    "TenantId",
    "TenantInactive",
    "TenantIsolationGuard",
    "TenantMismatch",
    "TenantNotFound",
    "TenantRepository",
    "TenantScope",
    "TenantStatus",
]
