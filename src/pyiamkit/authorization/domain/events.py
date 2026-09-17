"""Event names emitted by the Roles and Permissions model."""

from enum import StrEnum


class AuthorizationCatalogEventType(StrEnum):
    PERMISSION_REGISTERED = "PermissionRegistered"
    ROLE_CREATED = "RoleCreated"
    ROLE_DISABLED = "RoleDisabled"
    ROLE_PERMISSION_ADDED = "RolePermissionAdded"
    ROLE_PERMISSION_REMOVED = "RolePermissionRemoved"
    ROLE_SENSITIVITY_CHANGED = "RoleSensitivityChanged"
    ROLE_ASSIGNABILITY_CHANGED = "RoleAssignabilityChanged"
