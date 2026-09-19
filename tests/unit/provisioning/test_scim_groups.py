from datetime import UTC, datetime

import pytest

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    InvalidScimRequest,
    ProvisioningConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceId,
    ProvisioningResourceNotFound,
    ProvisioningSource,
    ScimEmail,
    ScimGroupInput,
    ScimGroupMember,
    ScimGroupPatchOperation,
    ScimGroupProvisioningService,
    ScimName,
    ScimPatchVerb,
    ScimProvisioningService,
    ScimUserInput,
)
from pyiamkit.provisioning.adapters import (
    InMemoryProvisioningGroupRepository,
    InMemoryProvisioningUserRepository,
)
from pyiamkit.tenancy import MembershipStatus, TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 11, 30, tzinfo=UTC)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _stack():
    clock = MutableClock(NOW)
    events = InMemoryDomainEventSink()
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    users = InMemoryProvisioningUserRepository()
    groups = InMemoryProvisioningGroupRepository()

    identity_service = IdentityApplicationService(
        repository=identities,
        clock=clock,
        event_sink=events,
    )
    tenancy_service = TenancyApplicationService(
        tenant_repository=tenants,
        membership_repository=memberships,
        identity_repository=identities,
        clock=clock,
        event_sink=events,
    )
    tenant = tenancy_service.create_tenant(name="ACME", slug="acme")
    tenant = tenancy_service.activate_tenant(tenant.id)
    source = ProvisioningSource(
        source_id="group-scim",
        tenant_id=tenant.id,
        base_url="https://iam.example.com/scim/v2",
    )
    user_service = ScimProvisioningService(
        source=source,
        identity_service=identity_service,
        identity_repository=identities,
        tenancy_service=tenancy_service,
        membership_repository=memberships,
        resource_repository=users,
        clock=clock,
        event_sink=events,
    )
    group_service = ScimGroupProvisioningService(
        source=source,
        group_repository=groups,
        user_repository=users,
        clock=clock,
        event_sink=events,
    )
    return (
        clock,
        user_service,
        group_service,
        users,
        groups,
        memberships,
        tenant,
        events,
    )


def _user(user_name: str, external_id: str) -> ScimUserInput:
    return ScimUserInput(
        user_name=user_name,
        external_id=external_id,
        display_name=user_name.split("@")[0].title(),
        name=ScimName(given_name=user_name.split("@")[0].title()),
        emails=(ScimEmail(user_name, primary=True),),
    )


def test_create_group_renders_managed_user_members_without_changing_membership_state() -> None:
    _, users_service, groups_service, users, _, memberships, _, _ = _stack()
    alice = users_service.create_user(_user("alice@example.com", "user-a"))
    bob = users_service.create_user(_user("bob@example.com", "user-b"))

    alice_mapping = users.get(ProvisioningResourceId.parse(alice.id))
    bob_mapping = users.get(ProvisioningResourceId.parse(bob.id))
    assert alice_mapping is not None
    assert bob_mapping is not None
    alice_membership = memberships.get(alice_mapping.membership_id)
    bob_membership = memberships.get(bob_mapping.membership_id)
    assert alice_membership is not None
    assert bob_membership is not None

    created = groups_service.create_group(
        ScimGroupInput(
            display_name="Finance Approvers",
            external_id="group-42",
            members=(
                ScimGroupMember(alice.id),
                ScimGroupMember(bob.id),
            ),
        )
    )

    assert created.group.display_name == "Finance Approvers"
    assert created.group.external_id == "group-42"
    assert {member.value for member in created.group.members} == {alice.id, bob.id}
    assert all(
        member.ref is not None and "/Users/" in member.ref for member in created.group.members
    )
    persisted_alice_membership = memberships.get(alice_mapping.membership_id)
    persisted_bob_membership = memberships.get(bob_mapping.membership_id)
    assert persisted_alice_membership is not None
    assert persisted_bob_membership is not None
    assert persisted_alice_membership.status is MembershipStatus.ACTIVE
    assert persisted_bob_membership.status is MembershipStatus.ACTIVE


def test_group_members_must_reference_active_users_from_same_source_and_tenant() -> None:
    _, _, groups_service, _, _, _, _, _ = _stack()

    with pytest.raises(InvalidScimRequest, match="valid User resource id"):
        groups_service.create_group(
            ScimGroupInput(
                display_name="Invalid",
                members=(ScimGroupMember("not-a-uuid"),),
            )
        )

    missing = str(ProvisioningResourceId.new())
    with pytest.raises(InvalidScimRequest, match="active managed User"):
        groups_service.create_group(
            ScimGroupInput(
                display_name="Missing",
                members=(ScimGroupMember(missing),),
            )
        )


def test_group_uniqueness_is_source_scoped_for_display_name_and_external_id() -> None:
    _, _, service, _, _, _, _, _ = _stack()
    service.create_group(ScimGroupInput(display_name="Data Team", external_id="group-1"))

    with pytest.raises(ProvisioningConflict, match="displayName"):
        service.create_group(ScimGroupInput(display_name="data team", external_id="group-2"))
    with pytest.raises(ProvisioningConflict, match="externalId"):
        service.create_group(ScimGroupInput(display_name="Other Team", external_id="group-1"))


def test_group_replace_and_patch_cover_members_etag_and_okta_pathless_replace() -> None:
    _, users_service, service, _, _, _, _, _ = _stack()
    alice = users_service.create_user(_user("alice@example.com", "user-a"))
    bob = users_service.create_user(_user("bob@example.com", "user-b"))
    carol = users_service.create_user(_user("carol@example.com", "user-c"))

    created = service.create_group(
        ScimGroupInput(
            display_name="Team",
            members=(ScimGroupMember(alice.id),),
        )
    )

    with pytest.raises(ProvisioningPreconditionFailed, match="version mismatch"):
        service.replace_group(
            ProvisioningResourceId.parse(created.id),
            ScimGroupInput(display_name="Team", members=()),
            if_match='W/"stale"',
        )

    replaced = service.replace_group(
        ProvisioningResourceId.parse(created.id),
        ScimGroupInput(
            display_name="Team Renamed",
            external_id="group-renamed",
            members=(ScimGroupMember(alice.id), ScimGroupMember(bob.id)),
        ),
        if_match=created.meta.version,
    )
    assert replaced.group.display_name == "Team Renamed"
    assert {member.value for member in replaced.group.members} == {alice.id, bob.id}

    patched = service.patch_group(
        ProvisioningResourceId.parse(created.id),
        (
            ScimGroupPatchOperation(
                ScimPatchVerb.ADD,
                "members",
                [{"value": carol.id}],
            ),
            ScimGroupPatchOperation(
                ScimPatchVerb.REMOVE,
                f'members[value eq "{alice.id}"]',
            ),
            ScimGroupPatchOperation(
                ScimPatchVerb.REPLACE,
                value={"displayName": "Final Team"},
            ),
        ),
        if_match=replaced.meta.version,
    )
    assert patched.group.display_name == "Final Team"
    assert {member.value for member in patched.group.members} == {bob.id, carol.id}


def test_delete_group_tombstones_group_but_preserves_users() -> None:
    _, users_service, service, users, groups, memberships, _, _ = _stack()
    alice = users_service.create_user(_user("alice@example.com", "user-a"))
    alice_mapping = users.get(ProvisioningResourceId.parse(alice.id))
    assert alice_mapping is not None

    created = service.create_group(
        ScimGroupInput(
            display_name="Disposable",
            members=(ScimGroupMember(alice.id),),
        )
    )
    group_id = ProvisioningResourceId.parse(created.id)
    service.delete_group(group_id, if_match=created.meta.version)

    with pytest.raises(ProvisioningResourceNotFound):
        service.get_group(group_id)
    stored = groups.get(group_id)
    assert stored is not None
    assert stored.member_ids == ()
    assert users.get(alice_mapping.id) is not None
    assert memberships.get(alice_mapping.membership_id).status is MembershipStatus.ACTIVE  # type: ignore[union-attr]


def test_group_lookup_and_pagination_are_deterministic() -> None:
    _, _, service, _, _, _, _, _ = _stack()
    service.create_group(ScimGroupInput(display_name="Alpha", external_id="a"))
    service.create_group(ScimGroupInput(display_name="Beta", external_id="b"))
    service.create_group(ScimGroupInput(display_name="Gamma", external_id="c"))

    assert service.find_by_display_name("beta").group.external_id == "b"  # type: ignore[union-attr]
    assert service.find_by_external_id("c").group.display_name == "Gamma"  # type: ignore[union-attr]
    page = service.list_groups(start_index=2, count=1)
    assert page.total_results == 3
    assert page.items_per_page == 1
    assert page.resources[0].group.display_name == "Beta"
