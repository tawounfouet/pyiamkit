from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.operations import (
    RevocationMarker,
    RevocationRegistry,
    RevocationTargetType,
    StateVersion,
)
from pyiamkit.operations.adapters import InMemoryRevocationRegistry
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 10, 1, 4, 0, tzinfo=UTC)


def _assert_registry_contract(registry: RevocationRegistry) -> None:
    assert registry is not None


def test_revocation_marker_normalizes_and_preserves_metadata() -> None:
    tenant_id = TenantId.new()
    marker = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id=" membership-42 ",
        revoked_at=NOW,
        reason_code=" suspended ",
        tenant_id=tenant_id,
        expires_at=NOW + timedelta(minutes=10),
        source_version=StateVersion(3),
    )

    assert marker.target_id == "membership-42"
    assert marker.reason_code == "suspended"
    assert marker.tenant_id == tenant_id
    assert marker.source_version == StateVersion(3)


@pytest.mark.parametrize(
    "target_type",
    [
        RevocationTargetType.IDENTITY,
        RevocationTargetType.MEMBERSHIP,
        RevocationTargetType.ROLE_BINDING,
        RevocationTargetType.TENANT,
    ],
)
def test_reactivable_targets_require_source_version(
    target_type: RevocationTargetType,
) -> None:
    with pytest.raises(ValueError, match="source_version is required"):
        RevocationMarker(
            target_type=target_type,
            target_id="target-1",
            revoked_at=NOW,
            reason_code="suspended",
        )


def test_terminal_session_marker_can_omit_source_version() -> None:
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
        expires_at=NOW + timedelta(hours=1),
    )

    assert marker.source_version is None


def test_revocation_marker_temporal_boundaries_are_half_open() -> None:
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
        expires_at=NOW + timedelta(minutes=5),
    )

    assert marker.is_active(at=NOW - timedelta(microseconds=1)) is False
    assert marker.is_active(at=NOW) is True
    assert marker.is_active(at=NOW + timedelta(minutes=4, seconds=59)) is True
    assert marker.is_active(at=NOW + timedelta(minutes=5)) is False


def test_revocation_marker_version_applicability_detects_reactivation() -> None:
    marker = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-1",
        revoked_at=NOW,
        reason_code="suspended",
        source_version=StateVersion(4),
    )

    assert marker.applies_to(StateVersion(3)) is True
    assert marker.applies_to(StateVersion(4)) is True
    assert marker.applies_to(StateVersion(5)) is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_id", ""),
        ("reason_code", ""),
    ],
)
def test_revocation_marker_rejects_empty_text(field: str, value: str) -> None:
    kwargs = {
        "target_type": RevocationTargetType.SESSION,
        "target_id": "session-1",
        "revoked_at": NOW,
        "reason_code": "logout",
    }
    kwargs[field] = value

    with pytest.raises(ValueError, match="must not be empty"):
        RevocationMarker(**kwargs)


def test_revocation_marker_requires_utc_and_forward_expiry() -> None:
    with pytest.raises(ValueError, match="revoked_at must be UTC-aware"):
        RevocationMarker(
            target_type=RevocationTargetType.SESSION,
            target_id="session-1",
            revoked_at=NOW.replace(tzinfo=None),
            reason_code="logout",
        )

    with pytest.raises(ValueError, match="expires_at must be after revoked_at"):
        RevocationMarker(
            target_type=RevocationTargetType.SESSION,
            target_id="session-1",
            revoked_at=NOW,
            reason_code="logout",
            expires_at=NOW,
        )


def test_in_memory_registry_records_gets_and_checks_revocation() -> None:
    registry = InMemoryRevocationRegistry()
    _assert_registry_contract(registry)
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
        expires_at=NOW + timedelta(hours=1),
    )

    registry.record(marker)

    assert registry.get(RevocationTargetType.SESSION, " session-1 ") == marker
    assert (
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "session-1",
            at=NOW + timedelta(minutes=1),
        )
        is True
    )


def test_registry_duplicate_record_is_idempotent() -> None:
    registry = InMemoryRevocationRegistry()
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )

    registry.record(marker)
    registry.record(marker)

    assert registry.get(RevocationTargetType.SESSION, "session-1") == marker


def test_registry_ignores_older_marker_and_accepts_newer_revision() -> None:
    registry = InMemoryRevocationRegistry()
    older = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-1",
        revoked_at=NOW,
        reason_code="suspended",
        source_version=StateVersion(2),
    )
    newer = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-1",
        revoked_at=NOW + timedelta(minutes=1),
        reason_code="suspended_again",
        source_version=StateVersion(4),
    )

    registry.record(newer)
    registry.record(older)

    assert registry.get(RevocationTargetType.MEMBERSHIP, "membership-1") == newer


def test_registry_rejects_conflicting_marker_for_same_revision() -> None:
    registry = InMemoryRevocationRegistry()
    first = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-1",
        revoked_at=NOW,
        reason_code="suspended",
        source_version=StateVersion(3),
    )
    conflicting = RevocationMarker(
        target_type=RevocationTargetType.MEMBERSHIP,
        target_id="membership-1",
        revoked_at=NOW + timedelta(seconds=1),
        reason_code="different_reason",
        source_version=StateVersion(3),
    )
    registry.record(first)

    with pytest.raises(ValueError, match="same target revision"):
        registry.record(conflicting)


def test_registry_isolates_same_target_id_by_target_type() -> None:
    registry = InMemoryRevocationRegistry()
    session_marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="shared-id",
        revoked_at=NOW,
        reason_code="logout",
    )
    binding_marker = RevocationMarker(
        target_type=RevocationTargetType.ROLE_BINDING,
        target_id="shared-id",
        revoked_at=NOW,
        reason_code="revoked",
        source_version=StateVersion(1),
    )

    registry.record(session_marker)
    registry.record(binding_marker)

    assert registry.get(RevocationTargetType.SESSION, "shared-id") == session_marker
    assert registry.get(RevocationTargetType.ROLE_BINDING, "shared-id") == binding_marker


def test_registry_preserves_tenant_metadata() -> None:
    registry = InMemoryRevocationRegistry()
    tenant_id = TenantId.new()
    marker = RevocationMarker(
        target_type=RevocationTargetType.TENANT,
        target_id=str(tenant_id),
        revoked_at=NOW,
        reason_code="suspended",
        tenant_id=tenant_id,
        source_version=StateVersion(7),
    )

    registry.record(marker)

    stored = registry.get(RevocationTargetType.TENANT, str(tenant_id))
    assert stored is not None
    assert stored.tenant_id == tenant_id
    assert stored.source_version == StateVersion(7)


def test_expired_marker_remains_inspectable_but_is_not_active() -> None:
    registry = InMemoryRevocationRegistry()
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


def test_registry_validates_utc_even_when_target_is_unknown() -> None:
    registry = InMemoryRevocationRegistry()

    with pytest.raises(ValueError, match="at must be UTC-aware"):
        registry.is_revoked(
            RevocationTargetType.SESSION,
            "missing-session",
            at=NOW.replace(tzinfo=None),
        )


def test_registry_rejects_invalid_lookup_identifier() -> None:
    registry = InMemoryRevocationRegistry()

    with pytest.raises(ValueError, match="target_id must not be empty"):
        registry.get(RevocationTargetType.SESSION, "   ")


def test_registry_handles_concurrent_duplicate_records() -> None:
    registry = InMemoryRevocationRegistry()
    marker = RevocationMarker(
        target_type=RevocationTargetType.SESSION,
        target_id="session-1",
        revoked_at=NOW,
        reason_code="logout",
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        tuple(executor.map(lambda _: registry.record(marker), range(100)))

    assert registry.get(RevocationTargetType.SESSION, "session-1") == marker
