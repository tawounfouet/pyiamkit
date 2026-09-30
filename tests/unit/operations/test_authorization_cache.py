from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    AuthenticationEvidence,
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationRequest,
    AuthorizationResult,
    PermissionCode,
    ResourceDescriptor,
    RoleId,
)
from pyiamkit.identity import IdentityId
from pyiamkit.operations import (
    AuthorizationCache,
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
    SecurityStateStamp,
    StateVersion,
)
from pyiamkit.operations.adapters import InMemoryAuthorizationCache
from pyiamkit.tenancy import TenantId, TenantScope

NOW = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)


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


def _request(
    *,
    identity_id: IdentityId | None = None,
    tenant_id: TenantId | None = None,
    correlation_id: str | None = "req-1",
    attributes: dict[str, object] | None = None,
    assurance_level: AssuranceLevel = AssuranceLevel.AAL2,
    mfa: bool = True,
) -> AuthorizationRequest:
    subject = identity_id or IdentityId.new()
    tenant = tenant_id or TenantId.new()
    return AuthorizationRequest(
        subject_id=subject,
        tenant_id=tenant,
        permission=PermissionCode("invoice.read"),
        scope=TenantScope(tenant),
        resource=ResourceDescriptor(
            resource_type="invoice",
            resource_id="inv-42",
            tenant_id=tenant,
            owner_id=subject,
            attributes=attributes or {"amount": Decimal("42.00"), "labels": {"b", "a"}},
        ),
        authentication=AuthenticationEvidence(
            assurance_level=assurance_level,
            mfa=mfa,
            authenticated_at=NOW,
        ),
        correlation_id=correlation_id,
    )


def _allow_entry(
    request: AuthorizationRequest,
    *,
    stamp: SecurityStateStamp | None = None,
    cached_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> AuthorizationCacheEntry:
    decision = AuthorizationDecision(
        result=AuthorizationResult.ALLOW,
        reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
        subject_id=request.subject_id,
        tenant_id=request.tenant_id,
        permission=request.permission,
        scope=request.scope,
        evaluated_at=cached_at,
        matched_role_id=RoleId.new(),
        resource=request.resource,
        correlation_id=request.correlation_id,
        explanation_path=("role permission matched",),
    )
    return AuthorizationCacheEntry(
        key=AuthorizationCacheKey.from_request(request),
        decision=CachedAuthorizationDecision.from_decision(decision),
        state_stamp=stamp or _zero_stamp(),
        cached_at=cached_at,
        expires_at=expires_at or cached_at + timedelta(seconds=30),
    )


def _assert_cache_contract(cache: AuthorizationCache) -> None:
    assert cache is not None


def test_authorization_cache_key_is_deterministic_and_excludes_correlation() -> None:
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    first = _request(
        identity_id=identity_id,
        tenant_id=tenant_id,
        correlation_id="req-1",
        attributes={
            "labels": {"b", "a"},
            "amount": Decimal("42.00"),
            "nested": {"z": 2, "a": 1},
        },
    )
    second = _request(
        identity_id=identity_id,
        tenant_id=tenant_id,
        correlation_id="req-2",
        attributes={
            "nested": {"a": 1, "z": 2},
            "amount": Decimal("42.0"),
            "labels": {"a", "b"},
        },
    )

    first_key = AuthorizationCacheKey.from_request(first)
    second_key = AuthorizationCacheKey.from_request(second)

    assert first_key == second_key
    assert len(first_key.digest) == 64
    assert str(identity_id) not in first_key.digest
    assert str(tenant_id) not in first_key.digest
    assert "invoice" not in first_key.digest


@pytest.mark.parametrize(
    ("assurance_level", "mfa"),
    [
        (AssuranceLevel.AAL1, True),
        (AssuranceLevel.AAL2, False),
        (AssuranceLevel.AAL3, True),
    ],
)
def test_authorization_cache_key_changes_with_authentication_evidence(
    assurance_level: AssuranceLevel,
    mfa: bool,
) -> None:
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    baseline = _request(identity_id=identity_id, tenant_id=tenant_id)
    changed = _request(
        identity_id=identity_id,
        tenant_id=tenant_id,
        assurance_level=assurance_level,
        mfa=mfa,
    )

    assert AuthorizationCacheKey.from_request(changed) != AuthorizationCacheKey.from_request(
        baseline
    )


def test_authorization_cache_key_changes_with_resource_attributes() -> None:
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    baseline = _request(
        identity_id=identity_id,
        tenant_id=tenant_id,
        attributes={"amount": Decimal("42")},
    )
    changed = _request(
        identity_id=identity_id,
        tenant_id=tenant_id,
        attributes={"amount": Decimal("43")},
    )

    assert AuthorizationCacheKey.from_request(changed) != AuthorizationCacheKey.from_request(
        baseline
    )


def test_authorization_cache_key_rejects_nondeterministic_resource_values() -> None:
    request = _request(attributes={"opaque": object()})

    with pytest.raises(TypeError, match="deterministic JSON-compatible"):
        AuthorizationCacheKey.from_request(request)


def test_authorization_cache_key_validates_sha256_shape() -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        AuthorizationCacheKey("not-a-digest")


def test_cache_entry_requires_utc_and_positive_validity_window() -> None:
    request = _request()
    valid = _allow_entry(request)

    assert valid.is_valid_for(_zero_stamp(), at=NOW + timedelta(seconds=1)) is True

    with pytest.raises(ValueError, match="expires_at must be after cached_at"):
        AuthorizationCacheEntry(
            key=valid.key,
            decision=valid.decision,
            state_stamp=valid.state_stamp,
            cached_at=NOW,
            expires_at=NOW,
        )

    with pytest.raises(ValueError, match="UTC-aware"):
        AuthorizationCacheEntry(
            key=valid.key,
            decision=valid.decision,
            state_stamp=valid.state_stamp,
            cached_at=NOW.replace(tzinfo=None),
            expires_at=NOW + timedelta(seconds=30),
        )


def test_cached_decision_rehydrates_fresh_identity_time_and_correlation() -> None:
    request = _request(correlation_id="original")
    original = AuthorizationDecision(
        result=AuthorizationResult.ALLOW,
        reason_code=AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
        subject_id=request.subject_id,
        tenant_id=request.tenant_id,
        permission=request.permission,
        scope=request.scope,
        evaluated_at=NOW,
        matched_role_id=RoleId.new(),
        resource=request.resource,
        correlation_id=request.correlation_id,
        explanation_path=("role permission matched",),
    )
    snapshot = CachedAuthorizationDecision.from_decision(original)
    replay_request = AuthorizationRequest(
        subject_id=request.subject_id,
        tenant_id=request.tenant_id,
        permission=request.permission,
        scope=request.scope,
        resource=request.resource,
        authentication=request.authentication,
        correlation_id="replayed-request",
    )

    replayed = snapshot.to_decision(
        replay_request,
        evaluated_at=NOW + timedelta(seconds=5),
    )

    assert replayed.id != original.id
    assert replayed.evaluated_at == NOW + timedelta(seconds=5)
    assert replayed.correlation_id == "replayed-request"
    assert replayed.result is original.result
    assert replayed.reason_code is original.reason_code
    assert replayed.matched_role_id == original.matched_role_id
    assert replayed.resource == request.resource


def test_in_memory_cache_returns_hit_only_for_exact_current_stamp() -> None:
    cache = InMemoryAuthorizationCache()
    _assert_cache_contract(cache)
    request = _request()
    entry = _allow_entry(request)
    cache.put(entry)

    hit = cache.get(
        entry.key,
        current_state=entry.state_stamp,
        at=NOW + timedelta(seconds=1),
    )

    assert hit == entry


def test_in_memory_cache_rejects_and_evicts_stale_stamp() -> None:
    cache = InMemoryAuthorizationCache()
    request = _request()
    entry = _allow_entry(request)
    cache.put(entry)
    stale_against = SecurityStateStamp(
        runtime_generation=StateVersion(0),
        identity=StateVersion(1),
        tenant=StateVersion(0),
        membership=StateVersion(0),
        subject_authorization=StateVersion(0),
        tenant_authorization=StateVersion(0),
        global_authorization=StateVersion(0),
        governance=StateVersion(0),
        authentication=StateVersion(0),
    )

    assert (
        cache.get(
            entry.key,
            current_state=stale_against,
            at=NOW + timedelta(seconds=1),
        )
        is None
    )
    assert (
        cache.get(
            entry.key,
            current_state=entry.state_stamp,
            at=NOW + timedelta(seconds=1),
        )
        is None
    )


def test_in_memory_cache_rejects_and_evicts_expired_entry() -> None:
    cache = InMemoryAuthorizationCache()
    request = _request()
    entry = _allow_entry(
        request,
        expires_at=NOW + timedelta(seconds=5),
    )
    cache.put(entry)

    assert cache.get(entry.key, current_state=entry.state_stamp, at=entry.expires_at) is None
    assert (
        cache.get(
            entry.key,
            current_state=entry.state_stamp,
            at=NOW + timedelta(seconds=1),
        )
        is None
    )


def test_in_memory_cache_does_not_cache_denials_by_default() -> None:
    cache = InMemoryAuthorizationCache()
    request = _request()
    key = AuthorizationCacheKey.from_request(request)
    denial = AuthorizationCacheEntry(
        key=key,
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.DENY,
            reason_code=AuthorizationReason.DENY_PERMISSION_NOT_GRANTED,
        ),
        state_stamp=_zero_stamp(),
        cached_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
    )

    cache.put(denial)

    assert cache.get(key, current_state=_zero_stamp(), at=NOW + timedelta(seconds=1)) is None


def test_in_memory_cache_can_explicitly_enable_deny_caching() -> None:
    cache = InMemoryAuthorizationCache(cache_denials=True)
    request = _request()
    key = AuthorizationCacheKey.from_request(request)
    denial = AuthorizationCacheEntry(
        key=key,
        decision=CachedAuthorizationDecision(
            result=AuthorizationResult.DENY,
            reason_code=AuthorizationReason.DENY_PERMISSION_NOT_GRANTED,
        ),
        state_stamp=_zero_stamp(),
        cached_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
    )

    cache.put(denial)

    assert cache.get(
        key,
        current_state=_zero_stamp(),
        at=NOW + timedelta(seconds=1),
    ) == denial


def test_in_memory_cache_delete_and_clear_are_idempotent() -> None:
    cache = InMemoryAuthorizationCache()
    first = _allow_entry(_request())
    second = _allow_entry(_request())
    cache.put(first)
    cache.put(second)

    cache.delete(first.key)
    cache.delete(first.key)

    assert cache.get(first.key, current_state=first.state_stamp, at=NOW) is None
    assert cache.get(second.key, current_state=second.state_stamp, at=NOW) == second

    cache.clear()
    cache.clear()

    assert cache.get(second.key, current_state=second.state_stamp, at=NOW) is None
