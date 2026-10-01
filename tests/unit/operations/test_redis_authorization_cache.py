from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch

import pytest
from redis.exceptions import RedisError

from pyiamkit.authorization import AuthorizationReason, AuthorizationResult
from pyiamkit.operations import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
    OperationalJsonCodec,
    RedisKeyspace,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters.redis import RedisAuthorizationCache

NOW = datetime(2026, 10, 1, 8, 30, tzinfo=UTC)


class FakeRedisClient:
    def __init__(self) -> None:
        self.values: dict[str, bytes | str] = {}
        self.pxat: dict[str, int] = {}
        self.deleted: list[str | bytes] = []

    def get(self, name: str) -> bytes | str | None:
        return self.values.get(name)

    def set(
        self,
        name: str,
        value: bytes,
        *,
        pxat: int,
    ) -> object:
        self.values[name] = value
        self.pxat[name] = pxat
        return True

    def delete(self, *names: str | bytes) -> object:
        for name in names:
            self.deleted.append(name)
            if isinstance(name, bytes):
                self.values.pop(name.decode(), None)
            else:
                self.values.pop(name, None)
        return len(names)

    def scan_iter(
        self,
        *,
        match: str,
        count: int,
    ) -> Iterator[str | bytes]:
        del count
        for key in tuple(self.values):
            if fnmatch(key, match):
                yield key


class FailingRedisClient(FakeRedisClient):
    def __init__(
        self,
        *,
        fail_get: bool = False,
        fail_set: bool = False,
        fail_delete: bool = False,
        fail_scan: bool = False,
    ) -> None:
        super().__init__()
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.fail_delete = fail_delete
        self.fail_scan = fail_scan

    def get(self, name: str) -> bytes | str | None:
        if self.fail_get:
            raise RedisError("redis unavailable")
        return super().get(name)

    def set(
        self,
        name: str,
        value: bytes,
        *,
        pxat: int,
    ) -> object:
        if self.fail_set:
            raise RedisError("redis unavailable")
        return super().set(name, value, pxat=pxat)

    def delete(self, *names: str | bytes) -> object:
        if self.fail_delete:
            raise RedisError("redis unavailable")
        return super().delete(*names)

    def scan_iter(
        self,
        *,
        match: str,
        count: int,
    ) -> Iterator[str | bytes]:
        if self.fail_scan:
            raise RedisError("redis unavailable")
        yield from super().scan_iter(match=match, count=count)


def _stamp(*, identity: int = 0) -> SecurityStateStamp:
    zero = StateVersion(0)
    return SecurityStateStamp(
        runtime_generation=zero,
        identity=StateVersion(identity),
        tenant=zero,
        membership=zero,
        subject_authorization=zero,
        tenant_authorization=zero,
        global_authorization=zero,
        governance=zero,
        authentication=zero,
    )


def _entry(
    *,
    key: AuthorizationCacheKey | None = None,
    state: SecurityStateStamp | None = None,
    allow: bool = True,
) -> AuthorizationCacheEntry:
    return AuthorizationCacheEntry(
        key=key or AuthorizationCacheKey("a" * 64),
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.ALLOW if allow else AuthorizationResult.DENY,
            reason_code=(
                AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH
                if allow
                else AuthorizationReason.DENY_PERMISSION_NOT_GRANTED
            ),
        ),
        state_stamp=state or _stamp(),
        cached_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def _cache(
    client: FakeRedisClient,
    *,
    cache_denials: bool = False,
    scan_count: int = 500,
) -> RedisAuthorizationCache:
    return RedisAuthorizationCache(
        client,
        keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
        cache_denials=cache_denials,
        scan_count=scan_count,
    )


def test_redis_authorization_cache_put_uses_absolute_expiry() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()

    cache.put(entry)

    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).authorization_cache(entry.key)
    assert redis_key in client.values
    assert client.pxat[redis_key] == int(entry.expires_at.timestamp() * 1000)


def test_redis_authorization_cache_round_trip_hit() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()
    cache.put(entry)

    loaded = cache.get(
        entry.key,
        current_state=entry.state_stamp,
        at=NOW + timedelta(seconds=1),
    )

    assert loaded == entry


def test_redis_authorization_cache_stale_stamp_is_miss_and_evicted() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()
    cache.put(entry)

    loaded = cache.get(
        entry.key,
        current_state=_stamp(identity=1),
        at=NOW + timedelta(seconds=1),
    )

    assert loaded is None
    assert client.values == {}
    assert client.deleted


def test_redis_authorization_cache_expired_entry_is_miss_and_evicted() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()
    cache.put(entry)

    loaded = cache.get(
        entry.key,
        current_state=entry.state_stamp,
        at=entry.expires_at,
    )

    assert loaded is None
    assert client.values == {}


def test_redis_authorization_cache_corrupt_payload_is_safe_miss() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).authorization_cache(entry.key)
    client.values[redis_key] = b"{not-json"

    loaded = cache.get(
        entry.key,
        current_state=entry.state_stamp,
        at=NOW,
    )

    assert loaded is None
    assert redis_key not in client.values


def test_redis_authorization_cache_rejects_wrong_embedded_key() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    requested = AuthorizationCacheKey("a" * 64)
    wrong_entry = _entry(key=AuthorizationCacheKey("b" * 64))
    requested_redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).authorization_cache(
        requested
    )
    client.values[requested_redis_key] = OperationalJsonCodec().encode_authorization_cache_entry(
        wrong_entry
    )

    loaded = cache.get(
        requested,
        current_state=wrong_entry.state_stamp,
        at=NOW,
    )

    assert loaded is None
    assert requested_redis_key not in client.values


def test_redis_authorization_cache_rejects_decode_responses_text_payload() -> None:
    client = FakeRedisClient()
    cache = _cache(client)
    entry = _entry()
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).authorization_cache(entry.key)
    client.values[redis_key] = "{}"

    assert cache.get(entry.key, current_state=entry.state_stamp, at=NOW) is None
    assert redis_key not in client.values


def test_redis_get_failure_becomes_cache_miss() -> None:
    cache = _cache(FailingRedisClient(fail_get=True))
    entry = _entry()

    assert cache.get(entry.key, current_state=entry.state_stamp, at=NOW) is None


def test_redis_write_and_delete_failures_are_best_effort() -> None:
    entry = _entry()
    write_cache = _cache(FailingRedisClient(fail_set=True))
    delete_cache = _cache(FailingRedisClient(fail_delete=True))

    write_cache.put(entry)
    delete_cache.delete(entry.key)


def test_redis_clear_failure_is_best_effort() -> None:
    cache = _cache(FailingRedisClient(fail_scan=True))

    cache.clear()


def test_redis_cache_does_not_store_denials_by_default() -> None:
    client = FakeRedisClient()
    cache = _cache(client)

    cache.put(_entry(allow=False))

    assert client.values == {}


def test_redis_cache_can_explicitly_store_denials() -> None:
    client = FakeRedisClient()
    cache = _cache(client, cache_denials=True)
    entry = _entry(allow=False)

    cache.put(entry)

    assert cache.get(entry.key, current_state=entry.state_stamp, at=NOW) == entry


def test_redis_cache_clear_deletes_only_current_authz_namespace() -> None:
    client = FakeRedisClient()
    cache = _cache(client, scan_count=2)
    first = _entry(key=AuthorizationCacheKey("a" * 64))
    second = _entry(key=AuthorizationCacheKey("b" * 64))
    cache.put(first)
    cache.put(second)
    unrelated = "pyiamkit:billing-api:test:v1:revocation:identity:deadbeef"
    client.values[unrelated] = b"keep"

    cache.clear()

    assert list(client.values) == [unrelated]


def test_redis_cache_validates_scan_count() -> None:
    client = FakeRedisClient()
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "test"))

    with pytest.raises(ValueError, match="greater than or equal to one"):
        RedisAuthorizationCache(client, keyspace=keyspace, scan_count=0)
