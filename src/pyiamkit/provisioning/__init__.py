"""Provisioning and SCIM public API."""

from .application import ProvisioningSource, ScimProvisioningService
from .domain import (
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
)
from .errors import (
    InvalidProvisioningResource,
    InvalidScimRequest,
    ProvisioningConflict,
    ProvisioningError,
    ProvisioningManagedStateConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceNotFound,
    UnsupportedScimPatch,
)
from .ports import ProvisioningUserRepository
from .scim import (
    SCIM_LIST_RESPONSE_SCHEMA,
    SCIM_PATCH_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimEmail,
    ScimListResponse,
    ScimMeta,
    ScimName,
    ScimPatchOperation,
    ScimPatchVerb,
    ScimUserInput,
    ScimUserResource,
    apply_user_patch,
)

__all__ = [
    "SCIM_LIST_RESPONSE_SCHEMA",
    "SCIM_PATCH_SCHEMA",
    "SCIM_USER_SCHEMA",
    "InvalidProvisioningResource",
    "InvalidScimRequest",
    "ProvisioningConflict",
    "ProvisioningError",
    "ProvisioningManagedStateConflict",
    "ProvisioningPreconditionFailed",
    "ProvisioningResourceId",
    "ProvisioningResourceNotFound",
    "ProvisioningResourceStatus",
    "ProvisioningSource",
    "ProvisioningUser",
    "ProvisioningUserRepository",
    "ScimEmail",
    "ScimListResponse",
    "ScimMeta",
    "ScimName",
    "ScimPatchOperation",
    "ScimPatchVerb",
    "ScimProvisioningService",
    "ScimUserInput",
    "ScimUserResource",
    "UnsupportedScimPatch",
    "apply_user_patch",
]
