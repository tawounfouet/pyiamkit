from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pyiamkit.authorization import AuthorizationReason, AuthorizationResult
from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    AuthorizationCache,
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    RevocationMarker,
    RevocationRegistry,
    RevocationTargetType,
    SecurityStateReader,
    SecurityStateStamp,
    SecurityStateWriter,
    StateVersion,
)
from pyiamkit.operations.adapters import (
    InMemoryAuthorizationCache,
    InMemoryRevocationRegistry,
    InMemorySecurityStateStore,
)
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemySecurityStateStore,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 10, 2, 7, 0, tzinfo=UTC)


def _assert_security_state_conformance(
    reader: SecurityStateReader,
    writer: SecurityStateWriter,
) -> None:
    identity_a = IdentityId.new()
    identity_b = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    initial = reader.stamp_for(identity_id=identity_a, tenant_id=tenant_a)
    assert {
        version.value
        for version in (
            initial.runtime_generation,
            initial.identity,
            initial.tenant,
            initial.membership,
            initial.subject_authorization,
            initial.tenant_authorization,
            initial.global_authorization,
            initial.governance,
            initial.authentication,
        )
    } == {0}

    assert writer.bump_runtime_generation() == StateVersion(1)
    assert writer.bump_identity(identity_a) == StateVersion(1)
    assert writer.bump_tenant(tenant_a) == StateVersion(1)
    assert writer.bump_membership(identity_a, tenant_a) == StateVersion(1)
    assert writer.bump_subject_authorization(identity_a, tenant_a) == StateVersion(1)
    assert writer.bump_tenant_authorization(tenant_a) == StateVersion(1)
    assert writer.bump_global_authorization() == StateVersion(1)
    assert writer.bump_governance(tenant_a) == StateVersion(1)
    assert writer.bump_authentication(identity_a) == StateVersion(1)

    subject_a_tenant_a = reader.stamp_for(identity_id=identity_a, tenant_id=tenant_a)
    assert subject_a_tenant_a == SecurityStateStamp(
        runtime_generation=StateVersion(1),
        identity=StateVersion(1),
        tenant=StateVersion(1),
        membership=StateVersion(1),
        subject_authorization=StateVersion(1),
        tenant_authorization=StateVersion(1),
        global_authorization=StateVersion(1),
        governance=StateVersion(1),
        authentication=StateVersion(1),
    )

    subject_b_same_tenant = reader.stamp_for(identity_id=identity_b, tenant_id=tenant_a)
    assert subject_b_same_tenant == SecurityStateStamp(
        runtime_generation=StateVersion(1),
        identity=StateVersion(0),
        tenant=StateVersion(1),
        membership=StateVersion(0),
        subject_authorization=StateVersion(0),
        tenant_authorization=StateVersion(1),
        global_authorization=StateVersion(1),
        governance=StateVersion(1),
        authentication=StateVersion(0),
    )

    same_subject_other_tenant = reader.stamp_for(identity_id=identity_a, tenant_id=tenant_b)
    assert same_subject_other_tenant == SecurityStateStamp(
        runtime_generation=StateVersion(1),
        identity=StateVersion(1),
        tenant=StateVersion(0),
        membership=StateVersion(0),
        subject_authorization=StateVersion(0),
        tenant_authorization=StateVersion(0),
        global_authorization=StateVersion(1),
        governance=StateVersion(0),
        authentication=StateVersion(1),
    )

    assert writer.bump_identity(identity_a) == StateVersion(2)
    assert writer.bump_identity(identity_a) == StateVersion(3)
    assert (
        reader.stamp_for(identity_id=identity_a, tenant_id=tenant_a).identity
        == StateVersion(3)
    )


@pytest.mark.conformance
def test_in_memory_security_state_contract() -> None:
    store = InMemorySecurityStateStore()

    _assert_security_state_conformance(store, store)


@pytest.mark.conformance
def test_sqlalchemy_sqlite_security_state_contract(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'operations.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        store = SqlAlchemySecurityStateStore(session)
        _assert_security_state_conformance(store, store)
    engine.dispose()


def _allow_entry(
    *,
    key: AuthorizationCacheKey,
    stamp: SecurityStateStamp,
    expires_at: datetime = NOW + timedelta(seconds=30),
) -> AuthorizationCacheEntry:
    return AuthorizationCacheEntry(
        key=key,
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.ALLOW,
            reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
        ),
        state_stamp=stamp,
        cached_at=NOW,
        expires_at=expires_at,
    )


def _deny_entry(
    *,
    key: AuthorizationCacheKey,
    stamp: SecurityStateStamp,
) -> AuthorizationCacheEntry:
    return AuthorizationCacheEntry(
        key=key,
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.DENY,
            reason_code=AuthorizationReason.DENY_PERMISSION_NOT_GRANTED,
        ),
        state_stamp=stamp,
        cached_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )


def _zero_stamp() -> SecurityStateStamp:
    zero = StateVersion(0)
    return SecurityStateStamp(
        runtime_generation=zero,
        identity=zero,
        tenant=zero,
        membership=zero,
        subject_authorization=zero,
        tenant_authorization=zero,
        global_authorization=zero,
        governance=zero,
        authentication=zero,
    )


def _assert_cache_conformance(cache: AuthorizationCache) -> None:
    key = AuthorizationCacheKey("a" * 64)
    stamp = _zero_stamp()
    entry = _allow_entry(key=key, stamp=stamp)

    assert cache.get(key, current_state=stamp, at=NOW) is None
    cache.put(entry)
    assert cache.get(key, current_state=stamp, at=NOW + timedelta(seconds=1)) == entry

    stale = SecurityStateStamp(
        runtime_generation=stamp.runtime_generation,
        identity=StateVersion(1),
        tenant=stamp.tenant,
        membership=stamp.membership,
        subject_authorization=stamp.subject_authorization,
        tenant_authorization=stamp.tenant_authorization,
        global_authorization=stamp.global_authorization,
        governance=stamp.governance,
        authentication=stamp.authentication,
    )
    assert cache.get(key, current_state=stale, at=NOW + timedelta(seconds=1)) is None

    cache.put(entry)
    assert cache.get(key, current_state=stamp, at=entry.expires_at) is None

    cache.put(entry)
    cache.delete(key)
    assert cache.get(key, current_state=stamp, at=NOW) is None

    first = AuthorizationCacheKey("b" * 64)
    second = AuthorizationCacheKey("c" * 64)
    cache.put(_allow_entry(key=first, stamp=stamp))
    cache.put(_allow_entry(key=second, stamp=stamp))
    cache.clear()
    assert cache.get(first, current_state=stamp, at=NOW) is None
    assert cache.get(second, current_state=stamp, at=NOW) is None


@pytest.mark.conformance
def test_in_memory_authorization_cache_contract() -> None:
    _assert_cache_conformance(InMemoryAuthorizationCache())


@pytest.mark.conformance
def test_authorization_cache_denials_are_opt_in() -> None:
    stamp = _zero_stamp()
    key = AuthorizationCacheKey("d" * 64)

    default = InMemoryAuthorizationCache()
    default.put(_deny_entry(key=key, stamp=stamp))
    assert default.get(key, current_state=stamp, at=NOW) is None

    enabled = InMemoryAuthorizationCache(cache_denials=True)
    deny = _deny_entry(key=key, stamp=stamp)
    enabled.put(deny)
    assert enabled.get(key, current_state=stamp, at=NOW) == deny


def _assert_revocation_conformance(registry: RevocationRegistry) -> None:
    terminal = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id=" session-1 ",
        revoked_at=NOW,
        reason_code=" logout ",
        expires_at=NOW + timedelta(minutes=5),
    )
    registry.record(terminal)
    registry.record(terminal)

    assert registry.get(RevocationTargetType.SESSION, "session-1") == terminal
    assert registry.is_revoked(RevocationTargetType.SESSION, "session-1", at=NOW)
    assert (
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "session-1",
            at=terminal.expires_at,
        )
        is False
    )

    newer = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-1",
        revoked_at=NOW + timedelta(seconds=2),
        reason_code="disabled",
        source_version=StateVersion(4),
    )
    older = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-1",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="suspended",
        source_version=StateVersion(2),
    )
    registry.record(newer)
    registry.record(older)
    assert registry.get(RevocationTargetType.IDENTITY, "identity-1") == newer

    conflicting = RevocationMarker(
        target_type=RevocationTargetType.IDENTITY,
        target_id="identity-1",
        revoked_at=NOW + timedelta(seconds=3),
        reason_code="different",
        source_version=StateVersion(4),
    )
    with pytest.raises(ValueError, match="same target revision"):
        registry.record(conflicting)


@pytest.mark.conformance
def test_in_memory_revocation_registry_contract() -> None:
    _assert_revocation_conformance(InMemoryRevocationRegistry())


@pytest.mark.conformance
def test_revocation_registry_requires_utc_lookup_time() -> None:
    registry = InMemoryRevocationRegistry()

    with pytest.raises(ValueError, match="UTC-aware"):
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "session-1",
            at=NOW.replace(tzinfo=None),
        )
