import os
import time
from datetime import UTC, datetime, timedelta

import pytest
from redis import Redis

from pyiamkit.authorization import AuthorizationReason, AuthorizationResult
from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    CacheNamespace,
    InvalidationEvent,
    InvalidationHandler,
    InvalidationKind,
    RedisKeyspace,
    RevocationMarker,
    RevocationTargetType,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters.redis import (
    RedisAuthorizationCache,
    RedisInvalidationPublisher,
    RedisInvalidationSubscriber,
    RedisRevocationRegistry,
    RedisSecurityStateProjection,
)
from pyiamkit.tenancy import TenantId

REDIS_URL = os.getenv("PYIAMKIT_TEST_REDIS_URL")


class RecordingHandler(InvalidationHandler):
    def __init__(self) -> None:
        self.events: list[InvalidationEvent] = []

    def handle(self, event: InvalidationEvent) -> bool:
        self.events.append(event)
        return True


@pytest.fixture
def redis_client() -> Redis:
    if REDIS_URL is None:
        pytest.skip("PYIAMKIT_TEST_REDIS_URL is not configured")
    client = Redis.from_url(REDIS_URL, decode_responses=False)
    client.ping()
    client.flushdb()
    try:
        yield client
    finally:
        client.flushdb()
        client.close()


def _stamp(
    *,
    identity: int = 0,
    tenant: int = 0,
    membership: int = 0,
) -> SecurityStateStamp:
    zero = StateVersion(0)
    return SecurityStateStamp(
        runtime_generation=zero,
        identity=StateVersion(identity),
        tenant=StateVersion(tenant),
        membership=StateVersion(membership),
        subject_authorization=zero,
        tenant_authorization=zero,
        global_authorization=zero,
        governance=zero,
        authentication=zero,
    )


def _entry(
    key: AuthorizationCacheKey,
    *,
    stamp: SecurityStateStamp,
    expires_at: datetime,
) -> AuthorizationCacheEntry:
    return AuthorizationCacheEntry(
        key=key,
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.ALLOW,
            reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
        ),
        state_stamp=stamp,
        cached_at=datetime.now(UTC),
        expires_at=expires_at,
    )


@pytest.mark.integration
def test_live_redis_authorization_cache_round_trip_pxat_and_namespace_clear(
    redis_client: Redis,
) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "live"))
    other_keyspace = RedisKeyspace(CacheNamespace("billing-api", "other"))
    cache = RedisAuthorizationCache(redis_client, keyspace=keyspace)
    other_cache = RedisAuthorizationCache(redis_client, keyspace=other_keyspace)
    stamp = _stamp(identity=1)
    first_key = AuthorizationCacheKey("a" * 64)
    second_key = AuthorizationCacheKey("b" * 64)
    other_key = AuthorizationCacheKey("c" * 64)
    expires_at = datetime.now(UTC) + timedelta(seconds=10)

    cache.put(_entry(first_key, stamp=stamp, expires_at=expires_at))
    cache.put(_entry(second_key, stamp=stamp, expires_at=expires_at))
    other_cache.put(_entry(other_key, stamp=stamp, expires_at=expires_at))

    assert cache.get(first_key, current_state=stamp, at=datetime.now(UTC)) is not None
    pttl = redis_client.pttl(keyspace.authorization_cache(first_key))
    assert 0 < pttl <= 10_000

    cache.clear()

    assert redis_client.exists(keyspace.authorization_cache(first_key)) == 0
    assert redis_client.exists(keyspace.authorization_cache(second_key)) == 0
    assert redis_client.exists(other_keyspace.authorization_cache(other_key)) == 1


@pytest.mark.integration
def test_live_redis_authorization_cache_pxat_expires_key(redis_client: Redis) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "expiry"))
    cache = RedisAuthorizationCache(redis_client, keyspace=keyspace)
    stamp = _stamp()
    key = AuthorizationCacheKey("d" * 64)
    expires_at = datetime.now(UTC) + timedelta(seconds=2)

    cache.put(_entry(key, stamp=stamp, expires_at=expires_at))
    assert redis_client.exists(keyspace.authorization_cache(key)) == 1

    time.sleep(2.2)

    assert redis_client.exists(keyspace.authorization_cache(key)) == 0


@pytest.mark.integration
def test_live_redis_revocation_registry_atomic_monotonic_lua(redis_client: Redis) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "revocation"))
    registry = RedisRevocationRegistry(redis_client, keyspace=keyspace)
    target_id = "identity-1"
    older = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id=target_id,
        revoked_at=datetime.now(UTC),
        reason_code="suspended",
        source_version=StateVersion(10**30),
    )
    newer = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id=target_id,
        revoked_at=datetime.now(UTC) + timedelta(seconds=1),
        reason_code="disabled",
        source_version=StateVersion(10**30 + 1),
    )

    registry.record(older)
    registry.record(newer)
    registry.record(older)

    assert registry.get(RevocationTargetType.IDENTITY, target_id) == newer
    registry.record(newer)

    conflicting = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id=target_id,
        revoked_at=newer.revoked_at + timedelta(seconds=1),
        reason_code="conflict",
        source_version=newer.source_version,
    )
    with pytest.raises(ValueError, match="same target revision"):
        registry.record(conflicting)


@pytest.mark.integration
def test_live_redis_security_state_projection_rejects_regression(redis_client: Redis) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "projection"))
    projection = RedisSecurityStateProjection(redis_client, keyspace=keyspace)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    current = _stamp(identity=5, tenant=4, membership=3)
    stale = _stamp(identity=6, tenant=3, membership=3)

    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=current)
    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=stale)

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == current


@pytest.mark.integration
def test_live_redis_pubsub_round_trip_and_duplicate_suppression(redis_client: Redis) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "pubsub"))
    handler = RecordingHandler()
    pubsub = redis_client.pubsub()
    subscriber = RedisInvalidationSubscriber(
        pubsub,
        keyspace=keyspace,
        handler=handler,
    )
    publisher = RedisInvalidationPublisher(redis_client, keyspace=keyspace)
    event = InvalidationEvent(
        kind=InvalidationKind.AUTHORIZATION,
        target_id="subject-1",
        state_version=StateVersion(7),
        occurred_at=datetime.now(UTC),
        tenant_id=TenantId.new(),
    )

    try:
        assert subscriber.subscribe() is True
        subscriber.poll(timeout=1.0)

        publisher.publish(event)
        assert subscriber.poll(timeout=2.0) is True
        assert handler.events == [event]

        publisher.publish(event)
        assert subscriber.poll(timeout=2.0) is False
        assert handler.events == [event]
    finally:
        pubsub.close()


@pytest.mark.integration
def test_live_redis_client_connection_recovery_preserves_adapter_semantics(
    redis_client: Redis,
) -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "reconnect"))
    cache = RedisAuthorizationCache(redis_client, keyspace=keyspace)
    stamp = _stamp(identity=2)
    key = AuthorizationCacheKey("e" * 64)
    entry = _entry(
        key,
        stamp=stamp,
        expires_at=datetime.now(UTC) + timedelta(seconds=10),
    )
    cache.put(entry)

    redis_client.connection_pool.disconnect()

    loaded = cache.get(key, current_state=stamp, at=datetime.now(UTC))
    assert loaded == entry


@pytest.mark.integration
def test_live_redis_namespaces_do_not_cross_environment_or_schema(redis_client: Redis) -> None:
    stamp = _stamp()
    key = AuthorizationCacheKey("f" * 64)
    expires_at = datetime.now(UTC) + timedelta(seconds=10)
    prod_v1 = RedisKeyspace(CacheNamespace("billing-api", "prod", schema_version=1))
    prod_v2 = RedisKeyspace(CacheNamespace("billing-api", "prod", schema_version=2))
    staging_v1 = RedisKeyspace(CacheNamespace("billing-api", "staging", schema_version=1))

    for keyspace in (prod_v1, prod_v2, staging_v1):
        RedisAuthorizationCache(redis_client, keyspace=keyspace).put(
            _entry(key, stamp=stamp, expires_at=expires_at)
        )

    redis_keys = {
        prod_v1.authorization_cache(key),
        prod_v2.authorization_cache(key),
        staging_v1.authorization_cache(key),
    }
    assert len(redis_keys) == 3
    assert all(redis_client.exists(redis_key) == 1 for redis_key in redis_keys)
