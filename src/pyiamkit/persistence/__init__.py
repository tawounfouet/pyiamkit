"""Optional persistence adapters for PyIAMKit.

The domain and application layers never depend on this package. Install an
adapter extra explicitly when persistence is required.
"""

from .errors import PersistenceError, PersistenceSerializationError

__all__ = ["PersistenceError", "PersistenceSerializationError"]
