from datetime import UTC, datetime

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    MICROSOFT_ENTRA_PROFILE,
    ProvisioningSource,
    ScimGroupProvisioningService,
    ScimHttpTransport,
    ScimProvisioningService,
)
from pyiamkit.provisioning.adapters import (
    InMemoryProvisioningGroupRepository,
    InMemoryProvisioningUserRepository,
)
from pyiamkit.provisioning.group_scim import SCIM_GROUP_SCHEMA
from pyiamkit.provisioning.scim import SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def _transport(*, entra: bool = False) -> ScimHttpTransport:
    clock = FrozenClock()
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
        source_id="group-http",
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
    if entra:
        return ScimHttpTransport(
            user_service,
            base_url="https://iam.example.com/scim/v2",
            group_service=group_service,
            provider_profile=MICROSOFT_ENTRA_PROFILE,
        )
    return ScimHttpTransport(
        user_service,
        base_url="https://iam.example.com/scim/v2",
        group_service=group_service,
    )


def _user_payload(user_name: str, external_id: str) -> dict[str, object]:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": user_name,
        "externalId": external_id,
        "displayName": user_name,
        "active": True,
    }


def _group_payload(
    display_name: str,
    external_id: str,
    members: list[str],
) -> dict[str, object]:
    return {
        "schemas": [SCIM_GROUP_SCHEMA],
        "displayName": display_name,
        "externalId": external_id,
        "members": [{"value": member} for member in members],
    }


def test_group_discovery_is_advertised_only_when_group_service_is_configured() -> None:
    transport = _transport()

    resource_types = transport.get_resource_types()
    schemas = transport.get_schemas()

    assert resource_types.body is not None
    assert resource_types.body["totalResults"] == 2
    ids = {resource["id"] for resource in resource_types.body["Resources"]}  # type: ignore[index]
    assert ids == {"User", "Group"}

    assert schemas.body is not None
    assert schemas.body["totalResults"] == 2
    schema_ids = {resource["id"] for resource in schemas.body["Resources"]}  # type: ignore[index]
    assert SCIM_USER_SCHEMA in schema_ids
    assert SCIM_GROUP_SCHEMA in schema_ids
    assert transport.get_resource_type("Group").status == 200
    assert transport.get_schema(SCIM_GROUP_SCHEMA).status == 200


def test_group_http_lifecycle_supports_members_filters_patch_and_etag() -> None:
    transport = _transport()
    alice = transport.create_user(_user_payload("alice@example.com", "alice-ext"))
    bob = transport.create_user(_user_payload("bob@example.com", "bob-ext"))
    assert alice.body is not None
    assert bob.body is not None
    alice_id = str(alice.body["id"])
    bob_id = str(bob.body["id"])

    created = transport.create_group(_group_payload("Finance", "group-ext", [alice_id]))
    assert created.status == 201
    assert created.body is not None
    group_id = str(created.body["id"])
    etag = created.headers["ETag"]
    assert created.headers["Location"].endswith(f"/Groups/{group_id}")
    assert created.body["members"][0]["value"] == alice_id  # type: ignore[index]

    fetched = transport.get_group(group_id)
    assert fetched.status == 200
    assert fetched.headers["ETag"] == etag

    filtered = transport.list_groups(filter_expression='displayName eq "finance"')
    assert filtered.status == 200
    assert filtered.body is not None
    assert filtered.body["totalResults"] == 1

    patched = transport.patch_group(
        group_id,
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": bob_id}],
                },
                {
                    "op": "replace",
                    "value": {"displayName": "Finance Team"},
                },
            ],
        },
        if_match=etag,
    )
    assert patched.status == 200
    assert patched.body is not None
    assert patched.body["displayName"] == "Finance Team"
    assert {member["value"] for member in patched.body["members"]} == {  # type: ignore[index]
        alice_id,
        bob_id,
    }

    removed = transport.patch_group(
        group_id,
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": f'members[value eq "{alice_id}"]',
                }
            ],
        },
        if_match=patched.headers["ETag"],
    )
    assert removed.status == 200
    assert removed.body is not None
    assert [member["value"] for member in removed.body["members"]] == [bob_id]  # type: ignore[index]

    stale = transport.replace_group(
        group_id,
        _group_payload("Stale", "stale-ext", []),
        if_match=etag,
    )
    assert stale.status == 412

    deleted = transport.delete_group(
        group_id,
        if_match=removed.headers["ETag"],
    )
    assert deleted.status == 204
    assert transport.get_group(group_id).status == 404
    assert transport.get_user(alice_id).status == 200
    assert transport.get_user(bob_id).status == 200


def test_group_http_rejects_unknown_member_and_duplicate_group() -> None:
    transport = _transport()
    unknown = "00000000-0000-0000-0000-000000000001"

    invalid = transport.create_group(_group_payload("Invalid", "invalid-ext", [unknown]))
    assert invalid.status == 400
    assert invalid.body is not None
    assert invalid.body["scimType"] == "invalidValue"

    created = transport.create_group(_group_payload("Finance", "group-1", []))
    assert created.status == 201
    duplicate = transport.create_group(_group_payload("finance", "group-2", []))
    assert duplicate.status == 409
    assert duplicate.body is not None
    assert duplicate.body["scimType"] == "uniqueness"


def test_entra_group_filter_accepts_unquoted_external_id() -> None:
    transport = _transport(entra=True)
    created = transport.create_group(_group_payload("Engineering", "group-42", []))
    assert created.status == 201

    response = transport.list_groups(filter_expression="externalId eq group-42")

    assert response.status == 200
    assert response.body is not None
    assert response.body["totalResults"] == 1
