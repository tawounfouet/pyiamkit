"""Tenancy-specific domain errors."""

from typing import ClassVar

from pyiamkit.shared import DomainError


class TenancyError(DomainError):
    code: ClassVar[str] = "TENANCY_ERROR"


class TenantNotFound(TenancyError):
    code = "TENANT_NOT_FOUND"

    def __init__(self, tenant_id: object) -> None:
        super().__init__(f"Tenant {tenant_id} was not found.")


class MembershipNotFound(TenancyError):
    code = "MEMBERSHIP_NOT_FOUND"

    def __init__(self, identity_id: object, tenant_id: object) -> None:
        super().__init__(f"No membership exists for identity {identity_id} in tenant {tenant_id}.")


class InvalidTenantTransition(TenancyError):
    code = "TENANT_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} tenant from {current_status} status.")


class InvalidMembershipTransition(TenancyError):
    code = "MEMBERSHIP_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} membership from {current_status} status.")


class TenantInactive(TenancyError):
    code = "TENANT_INACTIVE"


class MembershipInactive(TenancyError):
    code = "MEMBERSHIP_INACTIVE"


class TenantMismatch(TenancyError):
    code = "TENANT_MISMATCH"

    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}.")


class InvalidTenant(TenancyError):
    code = "TENANT_INVALID"


class InvalidMembership(TenancyError):
    code = "MEMBERSHIP_INVALID"
