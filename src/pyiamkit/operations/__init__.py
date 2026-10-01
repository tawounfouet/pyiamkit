"""Public distributed-operations primitives."""

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
)
from .errors import AuthorizationRuntimeUnavailable
from .invalidation import InvalidationKind
from .ports import (
    AuthorizationCache,
    RevocationRegistry,
    SecurityStateReader,
    SecurityStateWriter,
)
from .revocation import RevocationMarker, RevocationTargetType
from .runtime import DistributedAuthorizationRuntime
from .state import SecurityStateStamp, StateVersion

__all__ = [
    "AuthorizationCache",
    "AuthorizationCacheEntry",
    "AuthorizationCacheKey",
    "AuthorizationRuntimeUnavailable",
    "CacheNamespace",
    "CachedAuthorizationDecision",
    "DistributedAuthorizationRuntime",
    "InvalidationKind",
    "RevocationMarker",
    "RevocationRegistry",
    "RevocationTargetType",
    "SecurityStateReader",
    "SecurityStateStamp",
    "SecurityStateWriter",
    "StateVersion",
]
