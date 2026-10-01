"""Public distributed-operations primitives."""

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
)
from .errors import (
    AuthorizationRuntimeUnavailable,
    OperationalSerializationError,
    RevocationRegistryUnavailable,
)
from .invalidation import InvalidationEvent, InvalidationKind
from .keyspace import RedisKeyspace
from .ports import (
    AuthorizationCache,
    RevocationRegistry,
    SecurityStateReader,
    SecurityStateWriter,
)
from .revocation import RevocationMarker, RevocationTargetType
from .runtime import DistributedAuthorizationRuntime
from .serialization import OperationalJsonCodec
from .state import SecurityStateStamp, StateVersion

__all__ = [
    "AuthorizationCache",
    "AuthorizationCacheEntry",
    "AuthorizationCacheKey",
    "AuthorizationRuntimeUnavailable",
    "CacheNamespace",
    "CachedAuthorizationDecision",
    "DistributedAuthorizationRuntime",
    "InvalidationEvent",
    "InvalidationKind",
    "OperationalJsonCodec",
    "OperationalSerializationError",
    "RedisKeyspace",
    "RevocationMarker",
    "RevocationRegistryUnavailable",
    "RevocationRegistry",
    "RevocationTargetType",
    "SecurityStateReader",
    "SecurityStateStamp",
    "SecurityStateWriter",
    "StateVersion",
]
