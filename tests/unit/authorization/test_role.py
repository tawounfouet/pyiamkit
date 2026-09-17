from datetime import UTC, datetime

import pytest

from pyiamkit.authorization import (
    PermissionAlreadyAssigned,
    PermissionCode,
    PermissionNotAssigned,
    Role,
    RoleInactive,
    RoleStatus,
    RoleType,
)
from pyiamkit.tenancy import TenantId

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_role_contains_permissions_but_grants_nothing_to_a_subject() -> None:
    role = Role.create(name="Finance Manager", role_type=RoleType.BUSINESS, created_at=NOW)
    code = PermissionCode("invoice.approve")
    role.pull_events()
    role.add_permission(code, at=NOW)

    assert role.permissions == frozenset({code})
    assert not hasattr(role, "subject_id")


def test_duplicate_permission_assignment_is_rejected() -> None:
    role = Role.create(name="Reader", role_type=RoleType.BUSINESS, created_at=NOW)
    code = PermissionCode("invoice.read")
    role.add_permission(code, at=NOW)
    with pytest.raises(PermissionAlreadyAssigned):
        role.add_permission(code, at=NOW)


def test_removing_unknown_permission_is_rejected() -> None:
    role = Role.create(name="Reader", role_type=RoleType.BUSINESS, created_at=NOW)
    with pytest.raises(PermissionNotAssigned):
        role.remove_permission(PermissionCode("invoice.read"), at=NOW)


def test_disabled_role_cannot_be_mutated() -> None:
    role = Role.create(name="Reader", role_type=RoleType.BUSINESS, created_at=NOW)
    role.disable(at=NOW)
    assert role.status is RoleStatus.DISABLED
    with pytest.raises(RoleInactive):
        role.add_permission(PermissionCode("invoice.read"), at=NOW)


def test_role_can_be_explicitly_tenant_scoped() -> None:
    tenant_id = TenantId.new()
    role = Role.create(
        name="Finance Manager",
        role_type=RoleType.TENANT,
        tenant_id=tenant_id,
        created_at=NOW,
    )
    assert role.tenant_id == tenant_id


def test_role_sensitivity_and_assignability_are_explicit() -> None:
    role = Role.create(name="Admin Base", role_type=RoleType.SYSTEM, created_at=NOW)
    role.pull_events()
    role.set_sensitive(True, at=NOW)
    role.set_assignable(False, at=NOW)
    events = role.pull_events()

    assert role.sensitive is True
    assert role.assignable is False
    assert [event.event_type for event in events] == [
        "RoleSensitivityChanged",
        "RoleAssignabilityChanged",
    ]
