from collections.abc import Iterator

from redis.exceptions import RedisError

from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    CacheNamespace,
    ProjectingSecurityStateReader,
    RedisKeyspace,
    SecurityStateProjection,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters.redis import RedisSecurityStateProjection
from pyiamkit.tenancy import TenantId


class FakeRedisStateClient:
    _FIELDS = (
        "runtime_generation",
        "identity",
        "tenant",
        "membership",
        "subject_authorization",
        "tenant_authorization",
        "global_authorization",
        "governance",
        "authentication",
    )

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
        redis_key = keys_and_args[0]
        assert isinstance(redis_key, str)
        versions = keys_and_args[1:10]
        payload = keys_and_args[10]
        assert all(isinstance(value, str) and value.isdecimal() for value in versions)
        assert isinstance(payload, bytes)

        current = self.hashes.get(redis_key)
        if current is not None and "payload" in current:
            for field, candidate in zip(self._FIELDS, versions, strict=True):
                existing = current.get(field)
                if not isinstance(existing, str) or not existing.isdecimal():
                    return -2
                assert isinstance(candidate, str)
                if (len(candidate), candidate) < (len(existing), existing):
                    return 0

        self.hashes[redis_key] = {
            **{
                field: value
                for field, value in zip(self._FIELDS, versions, strict=True)
                if isinstance(value, str)
            },
            "payload": payload,
        }
        return 1

    def delete(self, *names: str | bytes) -> object:
        for name in names:
            self.deleted.append(name)
            key = name.decode() if isinstance(name, bytes) else name
            self.hashes.pop(key, None)
        return len(names)


class FailingRedisStateClient(FakeRedisStateClient):
    def __init__(self, *, fail_read: bool = False, fail_write: bool = False) -> None:
        super().__init__()
        self.fail_read = fail_read
        self.fail_write = fail_write

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


class StubAuthoritativeReader:
    def __init__(self, stamp: SecurityStateStamp) -> None:
        self.stamp = stamp
        self.calls = 0

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp:
        del identity_id, tenant_id
        self.calls += 1
        return self.stamp


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


def _projection(client: FakeRedisStateClient) -> RedisSecurityStateProjection:
    projection = RedisSecurityStateProjection(
        client,
        keyspace=RedisKeyspace(CacheNamespace("billing-api", "test")),
    )
    _assert_projection_contract(projection)
    return projection


def _assert_projection_contract(projection: SecurityStateProjection) -> None:
    assert projection is not None


def test_redis_security_state_projection_round_trip() -> None:
    projection = _projection(FakeRedisStateClient())
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    stamp = _stamp(identity=2, tenant=3, membership=4)

    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=stamp)

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == stamp


def test_redis_security_state_projection_rejects_stale_stamp() -> None:
    projection = _projection(FakeRedisStateClient())
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    newer = _stamp(identity=4, tenant=3)
    older = _stamp(identity=3, tenant=3)

    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=newer)
    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=older)

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == newer


def test_redis_security_state_projection_accepts_dominating_stamp() -> None:
    projection = _projection(FakeRedisStateClient())
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    first = _stamp(identity=2, tenant=3)
    newer = _stamp(identity=4, tenant=3, membership=1)

    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=first)
    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=newer)

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == newer


def test_redis_security_state_projection_ignores_incomparable_regression() -> None:
    projection = _projection(FakeRedisStateClient())
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    current = _stamp(identity=4, tenant=4)
    incomparable = _stamp(identity=5, tenant=3)

    projection.project(identity_id=identity_id, tenant_id=tenant_id, stamp=current)
    projection.project(
        identity_id=identity_id,
        tenant_id=tenant_id,
        stamp=incomparable,
    )

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == current


def test_redis_security_state_projection_corrupt_payload_is_miss_and_evicted() -> None:
    client = FakeRedisStateClient()
    projection = _projection(client)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    redis_key = RedisKeyspace(CacheNamespace("billing-api", "test")).security_state(
        identity_id,
        tenant_id,
    )
    client.hashes[redis_key] = {
        "payload": b"{bad-json",
    }

    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) is None
    assert redis_key not in client.hashes


def test_redis_security_state_projection_failures_are_best_effort() -> None:
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    read_projection = _projection(FailingRedisStateClient(fail_read=True))
    write_projection = _projection(FailingRedisStateClient(fail_write=True))

    assert read_projection.get(identity_id=identity_id, tenant_id=tenant_id) is None
    write_projection.project(
        identity_id=identity_id,
        tenant_id=tenant_id,
        stamp=_stamp(identity=1),
    )


def test_projecting_reader_returns_authoritative_state_and_warms_projection() -> None:
    client = FakeRedisStateClient()
    projection = _projection(client)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    authoritative = StubAuthoritativeReader(_stamp(identity=7))
    reader = ProjectingSecurityStateReader(authoritative, projection)

    returned = reader.stamp_for(identity_id=identity_id, tenant_id=tenant_id)

    assert returned == authoritative.stamp
    assert authoritative.calls == 1
    assert projection.get(identity_id=identity_id, tenant_id=tenant_id) == returned


def test_projecting_reader_survives_projection_outage() -> None:
    projection = _projection(FailingRedisStateClient(fail_write=True))
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    authoritative = StubAuthoritativeReader(_stamp(identity=9))
    reader = ProjectingSecurityStateReader(authoritative, projection)

    returned = reader.stamp_for(identity_id=identity_id, tenant_id=tenant_id)

    assert returned == authoritative.stamp
    assert authoritative.calls == 1
