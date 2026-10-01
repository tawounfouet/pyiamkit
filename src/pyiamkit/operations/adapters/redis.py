"""Redis-backed authorization cache adapter."""

from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Protocol

from redis.exceptions import RedisError

from ..cache import AuthorizationCacheEntry, AuthorizationCacheKey
from ..errors import (
    OperationalSerializationError,
    RevocationRegistryUnavailable,
)
from ..keyspace import RedisKeyspace
from ..ports import AuthorizationCache, RevocationRegistry
from ..revocation import RevocationMarker, RevocationTargetType
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


class _RedisRevocationClient(Protocol):
    def hget(self, name: str, key: str) -> bytes | str | None: ...

    def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | bytes | int,
    ) -> object: ...

    def delete(self, *names: str | bytes) -> object: ...


_REVOCATION_RECORD_SCRIPT = """
local function compare_decimal(left, right)
    if string.match(left, "^%d+$") == nil or string.match(right, "^%d+$") == nil then
        return nil
    end
    if string.len(left) < string.len(right) then
        return -1
    end
    if string.len(left) > string.len(right) then
        return 1
    end
    if left < right then
        return -1
    end
    if left > right then
        return 1
    end
    return 0
end

local current_kind = redis.call("HGET", KEYS[1], "order_kind")
if current_kind then
    local current_value = redis.call("HGET", KEYS[1], "order_value")
    local current_payload = redis.call("HGET", KEYS[1], "payload")
    if current_kind ~= ARGV[1] or current_value == false or current_payload == false then
        return -3
    end

    local comparison = compare_decimal(ARGV[2], current_value)
    if comparison == nil then
        return -3
    end
    if comparison < 0 then
        return 0
    end
    if comparison == 0 then
        if current_payload == ARGV[3] then
            return 1
        end
        return -2
    end
end

redis.call(
    "HSET",
    KEYS[1],
    "order_kind",
    ARGV[1],
    "order_value",
    ARGV[2],
    "payload",
    ARGV[3]
)
return 1
"""


class RedisRevocationRegistry(RevocationRegistry):
    """Redis-backed deny-fast registry with atomic monotonic marker replacement."""

    def __init__(
        self,
        client: _RedisRevocationClient,
        *,
        keyspace: RedisKeyspace,
        codec: OperationalJsonCodec | None = None,
    ) -> None:
        self._client = client
        self._keyspace = keyspace
        self._codec = codec or OperationalJsonCodec()

    def record(self, marker: RevocationMarker) -> None:
        redis_key = self._keyspace.revocation(marker.target_type, marker.target_id)
        payload = self._codec.encode_revocation_marker(marker)
        order_kind, order_value = self._ordering(marker)
        try:
            result = self._client.eval(
                _REVOCATION_RECORD_SCRIPT,
                1,
                redis_key,
                order_kind,
                order_value,
                payload,
            )
        except RedisError as exc:
            raise RevocationRegistryUnavailable(
                "Redis revocation registry write failed."
            ) from exc

        if result in (0, 1):
            return
        if result == -2:
            raise ValueError(
                "Conflicting revocation markers cannot share the same target revision"
            )
        raise RevocationRegistryUnavailable(
            "Redis revocation registry contains invalid ordering metadata."
        )

    def get(
        self,
        target_type: RevocationTargetType,
        target_id: str,
    ) -> RevocationMarker | None:
        redis_key = self._keyspace.revocation(target_type, target_id)
        try:
            raw = self._client.hget(redis_key, "payload")
        except RedisError as exc:
            raise RevocationRegistryUnavailable(
                "Redis revocation registry read failed."
            ) from exc

        if raw is None:
            return None
        if not isinstance(raw, bytes):
            self._best_effort_delete(redis_key)
            raise RevocationRegistryUnavailable(
                "Redis revocation registry returned a non-bytes payload."
            )

        try:
            marker = self._codec.decode_revocation_marker(raw)
        except OperationalSerializationError as exc:
            self._best_effort_delete(redis_key)
            raise RevocationRegistryUnavailable(
                "Redis revocation registry returned a corrupt payload."
            ) from exc

        normalized_target_id = target_id.strip()
        if marker.target_type is not target_type or marker.target_id != normalized_target_id:
            self._best_effort_delete(redis_key)
            raise RevocationRegistryUnavailable(
                "Redis revocation registry payload does not match its lookup key."
            )
        return marker

    def is_revoked(
        self,
        target_type: RevocationTargetType,
        target_id: str,
        *,
        at: datetime,
    ) -> bool:
        if at.tzinfo is None or at.utcoffset() != timedelta(0):
            raise ValueError("at must be UTC-aware")
        marker = self.get(target_type, target_id)
        return marker is not None and marker.is_active(at=at)

    @staticmethod
    def _ordering(marker: RevocationMarker) -> tuple[str, str]:
        if marker.source_version is not None:
            return "state_version", str(marker.source_version.value)
        return "revoked_at", str(int(marker.revoked_at.timestamp() * 1_000_000))

    def _best_effort_delete(self, redis_key: str) -> None:
        try:
            self._client.delete(redis_key)
        except RedisError:
            return


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
        at: datetime,
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
        except OperationalSerializationError:
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
