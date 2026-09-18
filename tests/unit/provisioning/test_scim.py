from datetime import UTC, datetime

import pytest

from pyiamkit.identity import IdentityApplicationService, IdentityStatus
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    ProvisioningConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceId,
    ProvisioningResourceNotFound,
    ProvisioningSource,
    ScimEmail,
    ScimName,
    ScimPatchOperation,
    ScimPatchVerb,
    ScimProvisioningService,
    ScimUserInput,
    UnsupportedScimPatch,
)
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.tenancy import MembershipStatus, TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


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
    resources = InMemoryProvisioningUserRepository()

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

    service = ScimProvisioningService(
        source=ProvisioningSource(
            source_id="entra-scim",
            tenant_id=tenant.id,
            base_url="https://iam.example.com/scim/v2",
        ),
        identity_service=identity_service,
        identity_repository=identities,
        tenancy_service=tenancy_service,
        membership_repository=memberships,
        resource_repository=resources,
        clock=clock,
        event_sink=events,
    )
    return clock, service, identities, memberships, resources, tenant


def _user(
    *,
    user_name: str = "alice@example.com",
    external_id: str | None = "ext-42",
    active: bool = True,
    display_name: str = "Alice Example",
    email: str = "alice@example.com",
) -> ScimUserInput:
    return ScimUserInput(
        user_name=user_name,
        external_id=external_id,
        display_name=display_name,
        active=active,
        name=ScimName(given_name="Alice", family_name="Example"),
        emails=(ScimEmail(email, primary=True),),
    )


def test_create_scim_user_creates_identity_membership_and_resource_metadata() -> None:
    _, service, identities, memberships, resources, tenant = _stack()

    created = service.create_user(_user())

    assert created.user.user_name == "alice@example.com"
    assert created.user.external_id == "ext-42"
    assert created.user.active is True
    assert created.meta.version.endswith('-0"')
    assert created.meta.location == f"https://iam.example.com/scim/v2/Users/{created.id}"

    resource = resources.get(ProvisioningResourceId.parse(created.id))
    assert resource is not None
    identity = identities.get(resource.identity_id)
    membership = memberships.get(resource.membership_id)
    assert identity is not None
    assert identity.status is IdentityStatus.ACTIVE
    assert identity.display_name == "Alice Example"
    assert str(identity.profile.primary_email) == "alice@example.com"
    assert identity.profile.first_name == "Alice"
    assert identity.profile.last_name == "Example"
    assert membership is not None
    assert membership.tenant_id == tenant.id
    assert membership.status is MembershipStatus.ACTIVE
    assert membership.source == "scim:entra-scim"


def test_inactive_scim_user_suspends_only_managed_tenant_membership() -> None:
    _, service, identities, memberships, resources, _ = _stack()

    created = service.create_user(_user(active=False))
    resource = resources.get(ProvisioningResourceId.parse(created.id))
    assert resource is not None
    identity = identities.get(resource.identity_id)
    membership = memberships.get(resource.membership_id)

    assert identity is not None
    assert identity.status is IdentityStatus.ACTIVE
    assert membership is not None
    assert membership.status is MembershipStatus.SUSPENDED


def test_username_is_case_insensitive_and_external_id_is_source_scoped_unique() -> None:
    _, service, _, _, _, _ = _stack()
    service.create_user(_user())

    with pytest.raises(ProvisioningConflict, match="userName"):
        service.create_user(
            _user(
                user_name="ALICE@EXAMPLE.COM",
                external_id="ext-other",
            )
        )

    with pytest.raises(ProvisioningConflict, match="externalId"):
        service.create_user(
            _user(
                user_name="bob@example.com",
                external_id="ext-42",
                email="bob@example.com",
            )
        )


def test_replace_requires_matching_etag_and_updates_membership_profile_and_version() -> None:
    _, service, identities, memberships, resources, _ = _stack()
    created = service.create_user(_user())
    resource_id = ProvisioningResourceId.parse(created.id)

    with pytest.raises(ProvisioningPreconditionFailed):
        service.replace_user(
            resource_id,
            _user(user_name="alice2@example.com"),
            if_match='W/"stale"',
        )

    replaced = service.replace_user(
        resource_id,
        _user(
            user_name="alice2@example.com",
            external_id="ext-43",
            active=False,
            display_name="Alice Updated",
            email="alice2@example.com",
        ),
        if_match=created.meta.version,
    )

    resource = resources.get(resource_id)
    assert resource is not None
    identity = identities.get(resource.identity_id)
    membership = memberships.get(resource.membership_id)
    assert replaced.meta.version != created.meta.version
    assert replaced.user.user_name == "alice2@example.com"
    assert identity is not None
    assert identity.display_name == "Alice Updated"
    assert str(identity.profile.primary_email) == "alice2@example.com"
    assert membership is not None
    assert membership.status is MembershipStatus.SUSPENDED


def test_patch_reactivates_membership_and_updates_supported_attributes() -> None:
    _, service, _, memberships, resources, _ = _stack()
    created = service.create_user(_user(active=False))
    resource_id = ProvisioningResourceId.parse(created.id)

    patched = service.patch_user(
        resource_id,
        (
            ScimPatchOperation(ScimPatchVerb.REPLACE, "active", True),
            ScimPatchOperation(
                ScimPatchVerb.REPLACE,
                "displayName",
                "Alice Reactivated",
            ),
            ScimPatchOperation(
                ScimPatchVerb.REPLACE,
                "emails",
                [{"value": "new@example.com", "primary": True, "type": "work"}],
            ),
        ),
        if_match=created.meta.version,
    )

    resource = resources.get(resource_id)
    assert resource is not None
    membership = memberships.get(resource.membership_id)
    assert patched.user.active is True
    assert patched.user.display_name == "Alice Reactivated"
    assert patched.user.primary_email == "new@example.com"
    assert membership is not None
    assert membership.status is MembershipStatus.ACTIVE


def test_unsupported_patch_path_fails_explicitly() -> None:
    _, service, _, _, _, _ = _stack()
    created = service.create_user(_user())

    with pytest.raises(UnsupportedScimPatch):
        service.patch_user(
            ProvisioningResourceId.parse(created.id),
            (
                ScimPatchOperation(
                    ScimPatchVerb.REPLACE,
                    "groups",
                    [{"value": "admins"}],
                ),
            ),
        )


def test_delete_tombstones_resource_revokes_membership_and_preserves_identity() -> None:
    _, service, identities, memberships, resources, _ = _stack()
    created = service.create_user(_user())
    resource_id = ProvisioningResourceId.parse(created.id)
    resource = resources.get(resource_id)
    assert resource is not None

    service.delete_user(resource_id, if_match=created.meta.version)

    membership = memberships.get(resource.membership_id)
    identity = identities.get(resource.identity_id)
    assert membership is not None
    assert membership.status is MembershipStatus.REVOKED
    assert identity is not None
    assert identity.status is IdentityStatus.ACTIVE
    with pytest.raises(ProvisioningResourceNotFound):
        service.get_user(resource_id)

    reprovisioned = service.create_user(_user())
    assert reprovisioned.id != created.id


def test_list_users_uses_scim_one_based_pagination() -> None:
    _, service, _, _, _, _ = _stack()
    service.create_user(_user(user_name="a@example.com", external_id="a", email="a@example.com"))
    service.create_user(_user(user_name="b@example.com", external_id="b", email="b@example.com"))
    service.create_user(_user(user_name="c@example.com", external_id="c", email="c@example.com"))

    page = service.list_users(start_index=2, count=1)

    assert page.total_results == 3
    assert page.start_index == 2
    assert page.items_per_page == 1
    assert page.resources[0].user.user_name == "b@example.com"
