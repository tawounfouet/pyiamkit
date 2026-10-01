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
from .handlers import AuthorizationCacheInvalidationHandler
from .invalidation import InvalidationEvent, InvalidationKind
from .keyspace import RedisKeyspace
from .ports import (
    AuthorizationCache,
    InvalidationHandler,
    InvalidationPublisher,
    RevocationRegistry,
    SecurityStateProjection,
    SecurityStateReader,
    SecurityStateWriter,
)
from .projection import ProjectingSecurityStateReader
from .revocation import RevocationMarker, RevocationTargetType
from .runtime import DistributedAuthorizationRuntime
from .serialization import OperationalJsonCodec
from .state import SecurityStateStamp, StateVersion

__all__ = [
    "AuthorizationCache",
    "AuthorizationCacheEntry",
    "AuthorizationCacheKey",
    "AuthorizationCacheInvalidationHandler",
    "AuthorizationRuntimeUnavailable",
    "CacheNamespace",
    "CachedAuthorizationDecision",
    "DistributedAuthorizationRuntime",
    "InvalidationEvent",
    "InvalidationHandler",
    "InvalidationPublisher",
    "InvalidationKind",
    "OperationalJsonCodec",
    "OperationalSerializationError",
    "ProjectingSecurityStateReader",
    "RedisKeyspace",
    "RevocationMarker",
    "RevocationRegistry",
    "RevocationRegistryUnavailable",
    "RevocationTargetType",
    "SecurityStateProjection",
    "SecurityStateReader",
    "SecurityStateStamp",
    "SecurityStateWriter",
    "StateVersion",
]
