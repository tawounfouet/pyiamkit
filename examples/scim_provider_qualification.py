from pyiamkit.provisioning import (
    MICROSOFT_ENTRA_PROFILE,
    OKTA_SCIM_PROFILE,
    ScimAttributeSelection,
    project_scim_resource,
)


group_payload = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "id": "group-1",
    "displayName": "Finance",
    "externalId": "provider-group-42",
    "members": [{"value": "user-1"}],
    "meta": {"resourceType": "Group"},
}

compact = project_scim_resource(
    group_payload,
    selection=ScimAttributeSelection(
        attributes=None,
        excluded_attributes=frozenset({"members"}),
    ),
)

assert "members" not in compact
assert compact["displayName"] == "Finance"
assert MICROSOFT_ENTRA_PROFILE.supports_groups is True
assert OKTA_SCIM_PROFILE.supports_groups is True

print(
    "SCIM provider qualification primitives OK:",
    MICROSOFT_ENTRA_PROFILE.kind.value,
    OKTA_SCIM_PROFILE.kind.value,
)
