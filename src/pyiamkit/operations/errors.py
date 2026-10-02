"""Operational runtime failures for distributed IAM coordination."""

from pyiamkit.shared import PyIAMKitError


class AuthorizationRuntimeUnavailable(PyIAMKitError):
    """Raised when a stable authoritative authorization snapshot cannot be obtained."""

    code = "AUTHORIZATION_RUNTIME_UNAVAILABLE"


class OperationalSerializationError(PyIAMKitError):
    """Raised when an operational wire payload is malformed or incompatible."""

    code = "OPERATIONAL_SERIALIZATION_ERROR"


class RevocationRegistryUnavailable(PyIAMKitError):
    """Raised when revocation state cannot be read with sufficient confidence."""

    code = "REVOCATION_REGISTRY_UNAVAILABLE"
