from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    AuthorizationCacheKey,
    CacheNamespace,
    RedisKeyspace,
    RevocationTargetType,
)
from pyiamkit.tenancy import TenantId


def test_redis_keyspace_is_versioned_and_opaque() -> None:
    namespace = CacheNamespace("billing-api", "prod", schema_version=3)
    keyspace = RedisKeyspace(namespace)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    cache_key = AuthorizationCacheKey("a" * 64)

    authz = keyspace.authorization_cache(cache_key)
    state = keyspace.security_state(identity_id, tenant_id)
    revocation = keyspace.revocation(RevocationTargetType.IDENTITY, str(identity_id))

    assert authz == f"pyiamkit:billing-api:prod:v3:authz:{cache_key.digest}"
    assert state.startswith("pyiamkit:billing-api:prod:v3:state:")
    assert revocation.startswith("pyiamkit:billing-api:prod:v3:revocation:identity:")
    assert str(identity_id) not in state
    assert str(identity_id) not in revocation
    assert str(tenant_id) not in state
    assert keyspace.invalidation_channel == "pyiamkit:billing-api:prod:v3:invalidation"


def test_redis_keyspace_is_deterministic_and_domain_separated() -> None:
    keyspace = RedisKeyspace(CacheNamespace("billing-api", "prod"))
    target = "same-target"

    identity_first = keyspace.revocation(RevocationTargetType.IDENTITY, target)
    identity_second = keyspace.revocation(RevocationTargetType.IDENTITY, target)
    session = keyspace.revocation(RevocationTargetType.SESSION, target)

    assert identity_first == identity_second
    assert identity_first != session


def test_namespace_version_changes_all_redis_names() -> None:
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    v1 = RedisKeyspace(CacheNamespace("billing-api", "prod", schema_version=1))
    v2 = RedisKeyspace(CacheNamespace("billing-api", "prod", schema_version=2))

    assert v1.security_state(identity_id, tenant_id) != v2.security_state(
        identity_id,
        tenant_id,
    )
    assert v1.invalidation_channel != v2.invalidation_channel
