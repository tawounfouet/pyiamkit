"""Redis-backed authorization cache adapter."""

from collections.abc import Iterator
from typing import Protocol

from redis.exceptions import RedisError

from ..cache import AuthorizationCacheEntry, AuthorizationCacheKey
from ..keyspace import RedisKeyspace
from ..ports import AuthorizationCache
from ..serialization import OperationalJsonCodec
from ..state import SecurityStateStamp


class _RedisAuthorizationClient(Protocol):
    def get(self, name: str) -> bytes | str | None: ...

    def set(
        self,
        name: str,
        value: bytes,
        *,
        pxat: int,
    ) -> object: ...

    def delete(self, *names: str | bytes) -> object: ...

    def scan_iter(
        self,
        *,
        match: str,
        count: int,
    ) -> Iterator[str | bytes]: ...


class RedisAuthorizationCache(AuthorizationCache):
    """Best-effort Redis projection of authorization-cache entries.

    Redis is never authoritative. Connection failures become cache misses/no-ops,
    while malformed, stale or mismatched payloads are rejected and evicted when
    possible.
    """

    def __init__(
        self,
        client: _RedisAuthorizationClient,
        *,
        keyspace: RedisKeyspace,
        codec: OperationalJsonCodec | None = None,
        cache_denials: bool = False,
        scan_count: int = 500,
    ) -> None:
        if isinstance(scan_count, bool) or not isinstance(scan_count, int):
            raise TypeError("scan_count must be an integer")
        if scan_count < 1:
            raise ValueError("scan_count must be greater than or equal to one")
        self._client = client
        self._keyspace = keyspace
        self._codec = codec or OperationalJsonCodec()
        self._cache_denials = cache_denials
        self._scan_count = scan_count

    def get(
        self,
        key: AuthorizationCacheKey,
        *,
        current_state: SecurityStateStamp,
        at: object,
    ) -> AuthorizationCacheEntry | None:
        redis_key = self._keyspace.authorization_cache(key)
        try:
            raw = self._client.get(redis_key)
        except RedisError:
            return None

        if raw is None:
            return None
        if not isinstance(raw, bytes):
            self._best_effort_delete(redis_key)
            return None

        try:
            entry = self._codec.decode_authorization_cache_entry(raw)
        except (TypeError, ValueError):
            self._best_effort_delete(redis_key)
            return None

        if entry.key != key:
            self._best_effort_delete(redis_key)
            return None
        if not entry.is_valid_for(current_state, at=at):
            self._best_effort_delete(redis_key)
            return None
        return entry

    def put(self, entry: AuthorizationCacheEntry) -> None:
        if not self._cache_denials and not entry.decision.allowed:
            return
        redis_key = self._keyspace.authorization_cache(entry.key)
        payload = self._codec.encode_authorization_cache_entry(entry)
        pxat = int(entry.expires_at.timestamp() * 1000)
        if pxat <= 0:
            return
        try:
            self._client.set(redis_key, payload, pxat=pxat)
        except RedisError:
            return

    def delete(self, key: AuthorizationCacheKey) -> None:
        self._best_effort_delete(self._keyspace.authorization_cache(key))

    def clear(self) -> None:
        batch: list[str | bytes] = []
        try:
            for key in self._client.scan_iter(
                match=self._keyspace.authorization_cache_pattern,
                count=self._scan_count,
            ):
                batch.append(key)
                if len(batch) >= self._scan_count:
                    self._client.delete(*batch)
                    batch.clear()
            if batch:
                self._client.delete(*batch)
        except RedisError:
            return

    def _best_effort_delete(self, redis_key: str) -> None:
        try:
            self._client.delete(redis_key)
        except RedisError:
            return
