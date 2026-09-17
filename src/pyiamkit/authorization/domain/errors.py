"""Roles and permissions domain errors."""

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


class PermissionAlreadyAssigned(AuthorizationModelError):
    code = "ROLE_PERMISSION_ALREADY_ASSIGNED"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} is already assigned to the role.")


class PermissionNotAssigned(AuthorizationModelError):
    code = "ROLE_PERMISSION_NOT_ASSIGNED"

    def __init__(self, code: object) -> None:
        super().__init__(f"Permission {code} is not assigned to the role.")
