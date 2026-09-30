from pyiamkit.provisioning import OKTA_SCIM_PROFILE
from pyiamkit.provisioning.group_scim import SCIM_GROUP_SCHEMA
from pyiamkit.provisioning.scim import SCIM_PATCH_SCHEMA, SCIM_USER_SCHEMA

from ._support import build_client, headers


def test_okta_offline_qualification_scenario() -> None:
    client = build_client(OKTA_SCIM_PROFILE, source_id="okta-qualification")

    precreate = client.get(
        "/scim/v2/Users",
        headers=headers(),
        params={"filter": 'userName eq "alice@example.com"'},
    )
    assert precreate.status_code == 200
    assert precreate.json()["totalResults"] == 0

    user = client.post(
        "/scim/v2/Users",
        headers=headers(),
        json={
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "alice@example.com",
            "externalId": "okta-user-a",
            "displayName": "Alice",
            "active": True,
        },
    )
    assert user.status_code == 201
    user_id = user.json()["id"]

    found = client.get(
        "/scim/v2/Users",
        headers=headers(),
        params={"filter": 'userName eq "alice@example.com"'},
    )
    assert found.status_code == 200
    assert found.json()["totalResults"] == 1

    group = client.post(
        "/scim/v2/Groups",
        headers=headers(),
        json={
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Finance",
            "externalId": "okta-group-42",
            "members": [],
        },
    )
    assert group.status_code == 201
    group_id = group.json()["id"]

    renamed = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**headers(), "If-Match": group.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "value": {
                        "id": group_id,
                        "displayName": "Finance Team",
                    },
                }
            ],
        },
    )
    assert renamed.status_code == 200
    assert renamed.json()["displayName"] == "Finance Team"

    added = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**headers(), "If-Match": renamed.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_id}],
                }
            ],
        },
    )
    assert added.status_code == 200
    assert [member["value"] for member in added.json()["members"]] == [user_id]

    removed = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**headers(), "If-Match": added.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": "members",
                    "value": [{"value": user_id}],
                }
            ],
        },
    )
    assert removed.status_code == 200
    assert removed.json()["members"] == []

    deactivated = client.patch(
        f"/scim/v2/Users/{user_id}",
        headers={**headers(), "If-Match": user.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False
