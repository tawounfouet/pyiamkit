"""Base exception hierarchy."""


class PyIAMKitError(Exception):
    """Base exception for supported PyIAMKit errors."""


class DomainError(PyIAMKitError):
    """Base exception for domain invariant violations."""
