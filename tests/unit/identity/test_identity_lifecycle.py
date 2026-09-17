from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.identity import (
    Identity,
    IdentityStatus,
    InvalidDisplayName,
    InvalidIdentityTransition,
)

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_new_user_is_pending_and_emits_created_event() -> None:
    identity = Identity.create_user(display_name=" Alice ", created_at=NOW)

    assert identity.status is IdentityStatus.PENDING
    assert identity.display_name == "Alice"
    assert identity.created_at == NOW
    assert identity.updated_at == NOW
    assert identity.version == 0
    events = identity.pull_events()
    assert [event.event_type for event in events] == ["IdentityCreated"]
    assert identity.pull_events() == ()


def test_identity_follows_supported_lifecycle() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()

    identity.activate(at=NOW + timedelta(minutes=1))
    assert identity.status is IdentityStatus.ACTIVE
    assert identity.activated_at == NOW + timedelta(minutes=1)

    identity.suspend(at=NOW + timedelta(minutes=2))
    assert identity.status is IdentityStatus.SUSPENDED
    assert identity.suspended_at == NOW + timedelta(minutes=2)

    identity.reactivate(at=NOW + timedelta(minutes=3))
    assert identity.status is IdentityStatus.ACTIVE
    assert identity.suspended_at is None

    identity.disable(at=NOW + timedelta(minutes=4), reason="offboarding")
    assert identity.status is IdentityStatus.DISABLED
    assert identity.disabled_at == NOW + timedelta(minutes=4)

    identity.archive(at=NOW + timedelta(minutes=5))
    assert identity.status is IdentityStatus.ARCHIVED
    assert identity.archived_at == NOW + timedelta(minutes=5)
    assert identity.version == 5
    assert identity.updated_at == NOW + timedelta(minutes=5)
    assert [event.event_type for event in identity.pull_events()] == [
        "IdentityActivated",
        "IdentitySuspended",
        "IdentityReactivated",
        "IdentityDisabled",
        "IdentityArchived",
    ]


def test_disabled_identity_cannot_be_reactivated() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.activate(at=NOW + timedelta(minutes=1))
    identity.disable(at=NOW + timedelta(minutes=2))

    with pytest.raises(InvalidIdentityTransition):
        identity.activate(at=NOW + timedelta(minutes=3))


def test_invalid_state_transitions_are_rejected() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)

    with pytest.raises(InvalidIdentityTransition):
        identity.suspend(at=NOW)
    with pytest.raises(InvalidIdentityTransition):
        identity.archive(at=NOW)
    with pytest.raises(InvalidIdentityTransition):
        identity.disable(at=NOW)


def test_archived_identity_is_terminal() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.activate(at=NOW)
    identity.disable(at=NOW)
    identity.archive(at=NOW)

    with pytest.raises(InvalidIdentityTransition):
        identity.reactivate(at=NOW)


def test_display_name_must_not_be_blank_or_too_long() -> None:
    with pytest.raises(InvalidDisplayName):
        Identity.create_user(display_name=" ", created_at=NOW)
    with pytest.raises(InvalidDisplayName):
        Identity.create_user(display_name="x" * 256, created_at=NOW)


def test_domain_requires_utc_timestamps() -> None:
    with pytest.raises(ValueError, match="UTC-aware"):
        Identity.create_user(display_name="Alice", created_at=datetime(2026, 9, 17, 12, 0))
