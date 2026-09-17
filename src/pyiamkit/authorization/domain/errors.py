"""Authorization domain errors."""

from typing import ClassVar

from pyiamkit.shared import DomainError


class AuthorizationModelError(DomainError):
    code: ClassVar[str] = "AUTHORIZATION_MODEL_ERROR"


class InvalidPermissionCode(AuthorizationModelError):
    code = "PERMISSION_CODE_INVALID"

    def __init__(self, value: str) -> None:
        super().__init__(f"Invalid permission code: {value!r}.")


class InvalidRoleName(AuthorizationModelError):
    code = "ROLE_NAME_INVALID"

    def __init__(self) -> None:
        super().__init__("Role name must contain between 1 and 255 characters.")


class InvalidRoleBinding(AuthorizationModelError):
    code = "ROLE_BINDING_INVALID"


class InvalidRoleBindingTransition(AuthorizationModelError):
    code = "ROLE_BINDING_INVALID_TRANSITION"

    def __init__(self, current_status: object, action: str) -> None:
        super().__init__(f"Cannot {action} RoleBinding from {current_status} status.")


class PermissionNotFound(AuthorizationModelError):
    code = "PERMISSION_NOT_FOUND"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} was not found.")


class PermissionAlreadyExists(AuthorizationModelError):
    code = "PERMISSION_ALREADY_EXISTS"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} already exists.")


class RoleNotFound(AuthorizationModelError):
    code = "ROLE_NOT_FOUND"

    def __init__(self, role_id: object) -> None:
        super().__init__(f"Role {role_id} was not found.")


class RoleAlreadyExists(AuthorizationModelError):
    code = "ROLE_ALREADY_EXISTS"

    def __init__(self, name: str) -> None:
        super().__init__(f"Role {name!r} already exists in this role namespace.")


class RoleInactive(AuthorizationModelError):
    code = "ROLE_INACTIVE"

    def __init__(self, role_id: object) -> None:
        super().__init__(f"Role {role_id} is not active.")


class RoleNotAssignable(AuthorizationModelError):
    code = "ROLE_NOT_ASSIGNABLE"

    def __init__(self, role_id: object) -> None:
        super().__init__(f"Role {role_id} cannot be assigned directly.")


class RoleTenantMismatch(AuthorizationModelError):
    code = "ROLE_TENANT_MISMATCH"

    def __init__(self, role_tenant: object, target_tenant: object) -> None:
        super().__init__(f"Role tenant {role_tenant} does not match target tenant {target_tenant}.")


class RoleBindingNotFound(AuthorizationModelError):
    code = "ROLE_BINDING_NOT_FOUND"

    def __init__(self, binding_id: object) -> None:
        super().__init__(f"RoleBinding {binding_id} was not found.")


class RoleBindingAlreadyExists(AuthorizationModelError):
    code = "ROLE_BINDING_ALREADY_EXISTS"

    def __init__(self) -> None:
        super().__init__("An active equivalent RoleBinding already exists.")


class PermissionAlreadyAssigned(AuthorizationModelError):
    code = "ROLE_PERMISSION_ALREADY_ASSIGNED"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} is already assigned to the role.")


class PermissionNotAssigned(AuthorizationModelError):
    code = "ROLE_PERMISSION_NOT_ASSIGNED"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} is not assigned to the role.")


class RoleHierarchyError(AuthorizationModelError):
    code = "ROLE_HIERARCHY_ERROR"


class RoleHierarchyCycle(RoleHierarchyError):
    code = "ROLE_HIERARCHY_CYCLE"

    def __init__(self, role_id: object, parent_role_id: object) -> None:
        super().__init__(f"Linking role {role_id} to parent {parent_role_id} would create a cycle.")


class RoleHierarchyTenantMismatch(RoleHierarchyError):
    code = "ROLE_HIERARCHY_TENANT_MISMATCH"

    def __init__(self, child_tenant: object, parent_tenant: object) -> None:
        super().__init__(
            f"Role hierarchy tenant mismatch: child={child_tenant}, parent={parent_tenant}."
        )


class RoleHierarchyUnavailable(RoleHierarchyError):
    code = "ROLE_HIERARCHY_UNAVAILABLE"

    def __init__(self, role_id: object) -> None:
        super().__init__(f"Role hierarchy references unavailable role {role_id}.")


class RoleHierarchyDepthExceeded(RoleHierarchyError):
    code = "ROLE_HIERARCHY_DEPTH_EXCEEDED"

    def __init__(self, max_depth: int) -> None:
        super().__init__(f"Role hierarchy exceeds configured maximum depth {max_depth}.")


class InvalidGovernanceRule(AuthorizationModelError):
    code = "GOVERNANCE_RULE_INVALID"


class StaticSoDViolation(AuthorizationModelError):
    code = "SOD_STATIC_VIOLATION"

    def __init__(self, rule_id: object) -> None:
        self.rule_id = rule_id
        super().__init__(f"Role assignment violates static SoD rule {rule_id}.")
