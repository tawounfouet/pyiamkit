"""Persistence adapter errors."""

from pyiamkit.shared import PyIAMKitError


class PersistenceError(PyIAMKitError):
    """Base exception for persistence-adapter failures."""


class PersistenceSerializationError(PersistenceError):
    """Raised when extensible metadata cannot be represented as JSON."""
