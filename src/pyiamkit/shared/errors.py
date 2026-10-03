"""Base exception hierarchy."""

from typing import ClassVar


class PyIAMKitError(Exception):
    """Base exception for supported PyIAMKit runtime errors."""

    code: ClassVar[str] = "PYIAMKIT_ERROR"


class DomainError(PyIAMKitError):
    """Base exception for domain invariant violations."""

    code: ClassVar[str] = "DOMAIN_ERROR"
