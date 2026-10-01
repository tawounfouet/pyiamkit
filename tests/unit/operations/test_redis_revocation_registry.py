from datetime import UTC, datetime, timedelta

import pytest
from redis.exceptions import RedisError

from pyiamkit.operations import (
    CacheNamespace,
    OperationalJsonCodec,
    RedisKeyspace,
    RevocationMarker,
    RevocationRegistry,
    RevocationRegistryUnavailable,
    RevocationTargetType,
    StateVersion,
)
from pyiamkit.operations.adapters.redis import RedisRevocationRegistry
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class FakeRedisRevocationClient:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, bytes | str]] = {}
        self.deleted: list[str | bytes] = []

    def hget(self, name: str, key: str) -> bytes | str | None:
        return self.hashes.get(name, {}).get(key)

    def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | bytes | int,
    ) -> object:
        del script
        assert numkeys == 1
        redis_key, order_kind, order_value, payload = keys_and_args
        assert isinstance(redis_key, str)
        assert isinstance(order_kind, str)
        assert isinstance(order_value, str)
        assert order_value.isdecimal()
        assert isinstance(payload, bytes)

        current = self.hashes.get(redis_key)
        if current is not None:
            current_kind = current.get("order_kind")
            current_value = current.get("order_value")
            current_payload = current.get("payload")
            if (
                not isinstance(current_kind, str)
                or not isinstance(current_value, str)
                or not current_value.isdecimal()
                or not isinstance(current_payload, bytes)
            ):
                return -3
            if current_kind != order_kind:
                return -3
            if (len(order_value), order_value) < (len(current_value), current_value):
                return 0
            if order_value == current_value:
                return 1 if current_payload == payload else -2

        self.hashes[redis_key] = {
            "order_kind": order_kind,
            "order_value": order_value,
            "payload": payload,
        }
        return 1

    def delete(self, *names: str | bytes) -> object:
        for name in names:
            self.deleted.append(name)
            key = name.decode() if isinstance(name, bytes) else name
            self.hashes.pop(key, None)
        return len(names)


class FailingRedisRevocationClient(FakeRedisRevocationClient):
    def __init__(
        self,
        *,
        fail_read: bool = False,
        fail_write: bool = False,
        fail_delete: bool = False,
    ) -> None:
        super().__init__()
        self.fail_read = fail_read
        self.fail_write = fail_write
        self.fail_delete = fail_delete

    def hget(self, name: str, key: str) -> bytes | str | None:
        if self.fail_read:
            raise RedisError("redis unavailable")
        return super().hget(name, key)

    def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: str | bytes | int,
    ) -> object:
        if self.fail_write:
            raise RedisError("redis unavailable")
        return super().eval(script, numkeys, *keys_and_args)

    def delete(self, *names: str | bytes) -> object:
        if self.fail_delete:
            raise RedisError("redis unavailable")
        return super().delete(*names)


def _registry(
    client: FakeRedisRevocationClient,
) -> RedisRevocationRegistry:
    registry = RedisRevocationRegistry(
        client,
        keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
    )
    _assert_registry_contract(registry)
    return registry


def _assert_registry_contract(registry: RevocationRegistry) -> None:
    assert registry is not None


def test_redis_revocation_registry_round_trip() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    tenant_id = TenantId.new()
    marker = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-42",
        revoked_at=NOW,
        reason_code="suspended",
        tenant_id=tenant_id,
        source_version=StateVersion(3),
    )

    registry.record(marker)

    assert registry.get(RevocationTargetType.MEMBERSHIP, "membership-42") == marker
    assert registry.is_revoked(
        RevocationTargetType.MEMBERSHIP,
        "membership-42",
        at=NOW,
    )


def test_redis_revocation_registry_duplicate_record_is_idempotent() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )

    registry.record(marker)
    registry.record(marker)

    assert registry.get(RevocationTargetType.SESSION, "session-1") == marker
    assert len(client.hashes) == 1


def test_redis_registry_ignores_older_and_accepts_newer_version() -> None:
    registry = _registry(FakeRedisRevocationClient())
    older = RevocationMarker(
        target_type=RevocationTargetType.ROLE_BINDING,
        target_id="binding-1",
        revoked_at=NOW,
        reason_code="revoked",
        source_version=StateVersion(2),
    )
    newer = RevocationMarker(
        target_type=RevocationTargetType.ROLE_BINDING,
        target_id="binding-1",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="revoked_again",
        source_version=StateVersion(4),
    )

    registry.record(newer)
    registry.record(older)

    assert registry.get(RevocationTargetType.ROLE_BINDING, "binding-1") == newer


def test_redis_registry_rejects_conflicting_same_revision() -> None:
    registry = _registry(FakeRedisRevocationClient())
    first = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-1",
        revoked_at=NOW,
        reason_code="suspended",
        source_version=StateVersion(5),
    )
    conflicting = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-1",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="different_reason",
        source_version=StateVersion(5),
    )
    registry.record(first)

    with pytest.raises(ValueError, match="same target revision"):
        registry.record(conflicting)


def test_redis_registry_orders_terminal_session_markers_by_revoked_at() -> None:
    registry = _registry(FakeRedisRevocationClient())
    older = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )
    newer = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="security_logout",
    )

    registry.record(newer)
    registry.record(older)

    assert registry.get(RevocationTargetType.SESSION, "session-1") == newer


def test_expired_redis_marker_remains_inspectable_but_not_active() -> None:
    registry = _registry(FakeRedisRevocationClient())
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
        expires_at=NOW + timedelta(minutes=5),
    )
    registry.record(marker)

    assert registry.get(RevocationTargetType.SESSION, "session-1") == marker
    assert (
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "session-1",
            at=NOW + timedelta(minutes=5),
        )
        is False
    )


def test_redis_registry_corrupt_payload_is_unavailable_and_evicted() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "test"))
    redis_key = keyspace.revocation(RevocationTargetType.SESSION, "session-1")
    client.hashes[redis_key] = {
        "order_kind": "revoked_at",
        "order_value": "1",
        "payload": b"{not-json",
    }

    with pytest.raises(RevocationRegistryUnavailable, match="corrupt payload"):
        registry.get(RevocationTargetType.SESSION, "session-1")

    assert redis_key not in client.hashes


def test_redis_registry_non_bytes_payload_is_unavailable() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).revocation(
        RevocationTargetType.SESSION,
        "session-1",
    )
    client.hashes[redis_key] = {
        "order_kind": "revoked_at",
        "order_value": "1",
        "payload": "{}",
    }

    with pytest.raises(RevocationRegistryUnavailable, match="non-bytes"):
        registry.get(RevocationTargetType.SESSION, "session-1")


def test_redis_registry_rejects_payload_that_does_not_match_lookup_key() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "test"))
    redis_key = keyspace.revocation(RevocationTargetType.SESSION, "session-1")
    wrong = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-2",
        revoked_at=NOW,
        reason_code="logout",
    )
    client.hashes[redis_key] = {
        "order_kind": "revoked_at",
        "order_value": "1",
        "payload": OperationalJsonCodec().encode_revocation_marker(wrong),
    }

    with pytest.raises(RevocationRegistryUnavailable, match="does not match"):
        registry.get(RevocationTargetType.SESSION, "session-1")

    assert redis_key not in client.hashes


def test_redis_registry_read_failure_is_not_none() -> None:
    registry = _registry(FailingRedisRevocationClient(fail_read=True))

    with pytest.raises(RevocationRegistryUnavailable, match="read failed"):
        registry.get(RevocationTargetType.SESSION, "session-1")


def test_redis_registry_write_failure_is_explicit() -> None:
    registry = _registry(FailingRedisRevocationClient(fail_write=True))
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )

    with pytest.raises(RevocationRegistryUnavailable, match="write failed"):
        registry.record(marker)


def test_redis_registry_corrupt_order_metadata_blocks_replacement() -> None:
    client = FakeRedisRevocationClient()
    registry = _registry(client)
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).revocation(
        RevocationTargetType.SESSION,
        "session-1",
    )
    client.hashes[redis_key] = {
        "order_kind": "bad",
        "order_value": "not-an-int",
        "payload": b"{}",
    }
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )

    with pytest.raises(RevocationRegistryUnavailable, match="ordering metadata"):
        registry.record(marker)


def test_best_effort_eviction_failure_keeps_unavailability_explicit() -> None:
    client = FailingRedisRevocationClient(fail_delete=True)
    registry = _registry(client)
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).revocation(
        RevocationTargetType.SESSION,
        "session-1",
    )
    client.hashes[redis_key] = {
        "order_kind": "revoked_at",
        "order_value": "1",
        "payload": b"{bad-json",
    }

    with pytest.raises(RevocationRegistryUnavailable):
        registry.get(RevocationTargetType.SESSION, "session-1")


def test_redis_registry_validates_utc_for_missing_target() -> None:
    registry = _registry(FakeRedisRevocationClient())

    with pytest.raises(ValueError, match="at must be UTC-aware"):
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "missing-session",
            at=NOW.replace(tzinfo=None),
        )


def test_redis_registry_preserves_order_for_large_state_versions() -> None:
    registry = _registry(FakeRedisRevocationClient())
    older = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-large",
        revoked_at=NOW,
        reason_code="suspended",
        source_version=StateVersion(10**30),
    )
    newer = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-large",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="suspended_again",
        source_version=StateVersion(10**30 + 1),
    )

    registry.record(older)
    registry.record(newer)

    assert registry.get(RevocationTargetType.IDENTITY, "identity-large") == newer
