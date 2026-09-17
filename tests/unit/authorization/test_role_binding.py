from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authorization import (
    InvalidRoleBinding,
    InvalidRoleBindingTransition,
    RoleBinding,
    RoleBindingStatus,
    RoleId,
)
from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId, TenantScope

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def _binding() -> RoleBinding:
    tenant_id = TenantId.new()
    return RoleBinding.create(
        identity_id=IdentityId.new(),
        role_id=RoleId.new(),
        tenant_id=tenant_id,
        scope=TenantScope(tenant_id),
        created_at=NOW,
        valid_until=NOW + timedelta(days=1),
        justification=" Temporary access ",
    )


def test_binding_is_active_only_within_validity_window() -> None:
    binding = _binding()
    assert binding.status is RoleBindingStatus.ACTIVE
    assert binding.justification == "Temporary access"
    assert binding.is_active(at=NOW)
    assert not binding.is_active(at=NOW + timedelta(days=2))


def test_binding_lifecycle_is_explicit() -> None:
    binding = _binding()
    binding.pull_events()
    binding.suspend(at=NOW)
    binding.reactivate(at=NOW)
    binding.revoke(at=NOW)
    assert binding.status is RoleBindingStatus.REVOKED
    assert [event.event_type for event in binding.pull_events()] == [
        "RoleBindingSuspended",
        "RoleBindingReactivated",
        "RoleBindingRevoked",
    ]


def test_revoked_binding_cannot_be_reactivated() -> None:
    binding = _binding()
    binding.revoke(at=NOW)
    with pytest.raises(InvalidRoleBindingTransition):
        binding.reactivate(at=NOW)


def test_scope_tenant_must_match_binding_tenant() -> None:
    with pytest.raises(InvalidRoleBinding):
        RoleBinding.create(
            identity_id=IdentityId.new(),
            role_id=RoleId.new(),
            tenant_id=TenantId.new(),
            scope=TenantScope(TenantId.new()),
            created_at=NOW,
        )
