"""Operational invalidation handlers."""

from .invalidation import InvalidationEvent
from .ports import AuthorizationCache, InvalidationHandler


class AuthorizationCacheInvalidationHandler(InvalidationHandler):
    """Safely clear a local authorization cache for an accepted invalidation."""

    def __init__(self, cache: AuthorizationCache) -> None:
        self._cache = cache

    def handle(self, event: InvalidationEvent) -> bool:
        del event
        self._cache.clear()
        return True
