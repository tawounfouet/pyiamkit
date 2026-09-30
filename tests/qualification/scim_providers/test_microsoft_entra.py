from pyiamkit.provisioning import MICROSOFT_ENTRA_PROFILE
from pyiamkit.provisioning.group_scim import SCIM_GROUP_SCHEMA
from pyiamkit.provisioning.scim import SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA

from ._support import build_client, headers


def _user(user_name: str, external_id: str) -> dict[str, object]:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": user_name,
        "externalId": external_id,
        "displayName": user_name,
        "active": True,
    }


def test_microsoft_entra_offline_qualification_scenario() -> None:
    client = build_client(MICROSOFT_ENTRA_PROFILE, source_id="entra-qualification")

    for endpoint in (
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ):
        response = client.get(endpoint, headers=headers())
        assert response.status_code == 200

    alice = client.post(
        "/scim/v2/Users",
        headers=headers(),
        json=_user("alice@example.com", "entra-user-a"),
    )
    bob = client.post(
        "/scim/v2/Users",
        headers=headers(),
        json=_user("bob@example.com", "entra-user-b"),
    )
    assert alice.status_code == 201
    assert bob.status_code == 201
    alice_id = alice.json()["id"]
    bob_id = bob.json()["id"]

    user_lookup = client.get(
        "/scim/v2/Users",
        headers=headers(),
        params={"filter": "externalId eq entra-user-a"},
    )
    assert user_lookup.status_code == 200
    assert user_lookup.json()["totalResults"] == 1

    created_group = client.post(
        "/scim/v2/Groups",
        headers=headers(),
        json={
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Finance",
            "externalId": "entra-group-42",
            "members": [{"value": alice_id}],
        },
    )
    assert created_group.status_code == 201
    group_id = created_group.json()["id"]

    compact_group = client.get(
        f"/scim/v2/Groups/{group_id}",
        headers=headers(),
        params={"excludedAttributes": "members"},
    )
    assert compact_group.status_code == 200
    assert compact_group.json()["displayName"] == "Finance"
    assert "members" not in compact_group.json()

    compact_lookup = client.get(
        "/scim/v2/Groups",
        headers=headers(),
        params={
            "filter": 'displayName eq "Finance"',
            "excludedAttributes": "members",
        },
    )
    assert compact_lookup.status_code == 200
    assert compact_lookup.json()["totalResults"] == 1
    assert "members" not in compact_lookup.json()["Resources"][0]

    added = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**headers(), "If-Match": created_group.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": bob_id}],
                }
            ],
        },
    )
    assert added.status_code == 200
    assert {member["value"] for member in added.json()["members"]} == {alice_id, bob_id}

    removed = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**headers(), "If-Match": added.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": f'members[value eq "{alice_id}"]',
                }
            ],
        },
    )
    assert removed.status_code == 200
    assert [member["value"] for member in removed.json()["members"]] == [bob_id]

    deactivated = client.patch(
        f"/scim/v2/Users/{alice_id}",
        headers={**headers(), "If-Match": alice.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False
