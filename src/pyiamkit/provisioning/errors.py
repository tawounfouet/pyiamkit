"""Provisioning and SCIM domain errors."""

from typing import ClassVar

from pyiamkit.shared import DomainError


class ProvisioningError(DomainError):
    code: ClassVar[str] = "PROVISIONING_ERROR"


class InvalidProvisioningResource(ProvisioningError):
    code = "PROVISIONING_RESOURCE_INVALID"


class ProvisioningResourceNotFound(ProvisioningError):
    code = "PROVISIONING_RESOURCE_NOT_FOUND"

    def __init__(self, resource_id: object) -> None:
        super().__init__(f"Provisioning resource {resource_id} was not found.")


class ProvisioningConflict(ProvisioningError):
    code = "PROVISIONING_CONFLICT"


class ProvisioningPreconditionFailed(ProvisioningError):
    code = "PROVISIONING_PRECONDITION_FAILED"


class ProvisioningManagedStateConflict(ProvisioningError):
    code = "PROVISIONING_MANAGED_STATE_CONFLICT"


class UnsupportedScimPatch(ProvisioningError):
    code = "SCIM_PATCH_UNSUPPORTED"


class InvalidScimRequest(ProvisioningError):
    code = "SCIM_REQUEST_INVALID"
