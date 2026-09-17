"""Event names emitted by the authorization model."""

from enum import StrEnum


class AuthorizationCatalogEventType(StrEnum):
    PERMISSION_REGISTERED = "PermissionRegistered"
    ROLE_ASSIGNABILITY_CHANGED = "RoleAssignabilityChanged"
    ROLE_ASSIGNED = "RoleAssigned"
    ROLE_BINDING_EXPIRED = "RoleBindingExpired"
    ROLE_BINDING_REACTIVATED = "RoleBindingReactivated"
    ROLE_BINDING_REVOKED = "RoleBindingRevoked"
    ROLE_BINDING_SUSPENDED = "RoleBindingSuspended"
    ROLE_CREATED = "RoleCreated"
    ROLE_DISABLED = "RoleDisabled"
    ROLE_PERMISSION_ADDED = "RolePermissionAdded"
    ROLE_PERMISSION_REMOVED = "RolePermissionRemoved"
    ROLE_SENSITIVITY_CHANGED = "RoleSensitivityChanged"
