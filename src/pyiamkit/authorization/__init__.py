"""Public authorization API."""

from .application import RoleCatalogApplicationService
from .binding_application import RoleBindingApplicationService
from .domain.binding_value_objects import GrantSource, RoleBindingId, RoleBindingStatus
from .domain.decision import (
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationRequest,
    AuthorizationResult,
)
from .domain.errors import (
    AuthorizationModelError,
    InvalidPermissionCode,
    InvalidRoleBinding,
    InvalidRoleBindingTransition,
    InvalidRoleName,
    PermissionAlreadyAssigned,
    PermissionAlreadyExists,
    PermissionNotAssigned,
    PermissionNotFound,
    RoleAlreadyExists,
    RoleBindingAlreadyExists,
    RoleBindingNotFound,
    RoleHierarchyCycle,
    RoleHierarchyDepthExceeded,
    RoleHierarchyError,
    RoleHierarchyTenantMismatch,
    RoleHierarchyUnavailable,
    RoleInactive,
    RoleNotAssignable,
    RoleNotFound,
    RoleTenantMismatch,
)
from .domain.permission import Permission
from .domain.role import Role
from .domain.role_binding import RoleBinding
from .domain.value_objects import PermissionCode, RoleId, RoleStatus, RoleType
from .engine import AuthorizationDenied, AuthorizationEngine
from .hierarchy import RoleHierarchyApplicationService, RoleHierarchyResolver
from .ports import PermissionCatalogRepository, RoleBindingRepository, RoleRepository

__all__ = [
    "AuthorizationDecision",
    "AuthorizationDenied",
    "AuthorizationEngine",
    "AuthorizationModelError",
    "AuthorizationReason",
    "AuthorizationRequest",
    "AuthorizationResult",
    "GrantSource",
    "InvalidPermissionCode",
    "InvalidRoleBinding",
    "InvalidRoleBindingTransition",
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
    "RoleBinding",
    "RoleBindingAlreadyExists",
    "RoleBindingApplicationService",
    "RoleBindingId",
    "RoleBindingNotFound",
    "RoleBindingRepository",
    "RoleBindingStatus",
    "RoleCatalogApplicationService",
    "RoleHierarchyApplicationService",
    "RoleHierarchyCycle",
    "RoleHierarchyDepthExceeded",
    "RoleHierarchyError",
    "RoleHierarchyResolver",
    "RoleHierarchyTenantMismatch",
    "RoleHierarchyUnavailable",
    "RoleId",
    "RoleInactive",
    "RoleNotAssignable",
    "RoleNotFound",
    "RoleRepository",
    "RoleStatus",
    "RoleTenantMismatch",
    "RoleType",
]
