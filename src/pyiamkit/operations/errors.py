"""Operational runtime failures for distributed IAM coordination."""

from pyiamkit.shared import PyIAMKitError


class AuthorizationRuntimeUnavailable(PyIAMKitError):
    """Raised when a stable authoritative authorization snapshot cannot be obtained."""

    code = "AUTHORIZATION_RUNTIME_UNAVAILABLE"
