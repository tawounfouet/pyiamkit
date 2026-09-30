"""Public distributed-operations primitives."""

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
)
from .invalidation import InvalidationKind
from .ports import AuthorizationCache, SecurityStateReader, SecurityStateWriter
from .revocation import RevocationTargetType
from .state import SecurityStateStamp, StateVersion

__all__ = [
    "AuthorizationCache",
    "AuthorizationCacheEntry",
    "AuthorizationCacheKey",
    "CacheNamespace",
    "CachedAuthorizationDecision",
    "InvalidationKind",
    "RevocationTargetType",
    "SecurityStateReader",
    "SecurityStateStamp",
    "SecurityStateWriter",
    "StateVersion",
]
