"""Public distributed-operations primitives."""

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
)
from .invalidation import InvalidationKind
from .ports import (
    AuthorizationCache,
    RevocationRegistry,
    SecurityStateReader,
    SecurityStateWriter,
)
from .revocation import RevocationMarker, RevocationTargetType
from .state import SecurityStateStamp, StateVersion

__all__ = [
    "AuthorizationCache",
    "AuthorizationCacheEntry",
    "AuthorizationCacheKey",
    "CacheNamespace",
    "CachedAuthorizationDecision",
    "InvalidationKind",
    "RevocationMarker",
    "RevocationRegistry",
    "RevocationTargetType",
    "SecurityStateReader",
    "SecurityStateStamp",
    "SecurityStateWriter",
    "StateVersion",
]
