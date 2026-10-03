"""Persistence adapter errors."""

from typing import ClassVar

from pyiamkit.shared import PyIAMKitError


class PersistenceError(PyIAMKitError):
    """Base exception for persistence-adapter failures."""

    code: ClassVar[str] = "PERSISTENCE_ERROR"


class PersistenceSerializationError(PersistenceError):
    """Raised when extensible metadata cannot be represented as JSON."""

    code = "PERSISTENCE_SERIALIZATION_ERROR"
