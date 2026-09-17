"""Public beta Roles and Permissions API."""

from .application import RoleCatalogApplicationService
from .domain.errors import (
    AuthorizationModelError,
    InvalidPermissionCode,
    InvalidRoleName,
    PermissionAlreadyAssigned,
    PermissionAlreadyExists,
    PermissionNotAssigned,
    PermissionNotFound,
    RoleAlreadyExists,
    RoleInactive,
    RoleNotFound,
)
from .domain.permission import Permission
from .domain.role import Role
from .domain.value_objects import PermissionCode, RoleId, RoleStatus, RoleType
from .ports import PermissionCatalogRepository, RoleRepository

__all__ = [
    "AuthorizationModelError",
    "InvalidPermissionCode",
    "InvalidRoleName",
    "Permission",
    "PermissionAlreadyAssigned",
    "PermissionAlreadyExists",
    "PermissionCatalogRepository",
    "PermissionCode",
    "PermissionNotAssigned",
    "PermissionNotFound",
    "Role",
    "RoleAlreadyExists",
    "RoleCatalogApplicationService",
    "RoleId",
    "RoleInactive",
    "RoleNotFound",
    "RoleRepository",
    "RoleStatus",
    "RoleType",
]
