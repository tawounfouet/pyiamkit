from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import (
    InvalidMembershipTransition,
    Membership,
    MembershipStatus,
    TenantId,
)

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_membership_lifecycle_and_expiry() -> None:
    membership = Membership.create(
        identity_id=IdentityId.new(),
        tenant_id=TenantId.new(),
        created_at=NOW,
        valid_until=NOW + timedelta(days=1),
    )
    assert membership.status is MembershipStatus.PENDING

    membership.activate(at=NOW)
    assert membership.is_active(at=NOW)
    assert not membership.is_active(at=NOW + timedelta(days=2))

    membership.suspend(at=NOW)
    membership.reactivate(at=NOW)
    membership.expire(at=NOW + timedelta(days=1))
    assert membership.status is MembershipStatus.EXPIRED


def test_expired_membership_cannot_be_reactivated() -> None:
    membership = Membership.create(
        identity_id=IdentityId.new(), tenant_id=TenantId.new(), created_at=NOW
    )
    membership.activate(at=NOW)
    membership.expire(at=NOW)

    with pytest.raises(InvalidMembershipTransition):
        membership.reactivate(at=NOW)
