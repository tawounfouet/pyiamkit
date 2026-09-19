import pytest

from pyiamkit.provisioning import InvalidScimRequest
from pyiamkit.provisioning.http import (
    ScimAttributeSelection,
    parse_attribute_selection,
    project_scim_resource,
)


ALLOWED = frozenset({"displayName", "externalId", "members"})


def test_attribute_selection_is_case_insensitive_and_deduplicated() -> None:
    selection = parse_attribute_selection(
        attributes="displayName, MEMBERS,displayname",
        excluded_attributes="externalID",
        allowed_attributes=ALLOWED,
    )

    assert selection.attributes == frozenset({"displayName", "members"})
    assert selection.excluded_attributes == frozenset({"externalId"})


def test_projection_preserves_scim_always_returned_attributes() -> None:
    payload = {
        "schemas": ["urn:test"],
        "id": "group-1",
        "displayName": "Finance",
        "externalId": "ext-1",
        "members": [{"value": "user-1"}],
        "meta": {"resourceType": "Group"},
    }

    projected = project_scim_resource(
        payload,
        selection=ScimAttributeSelection(
            attributes=frozenset({"displayName", "members"}),
            excluded_attributes=frozenset({"members"}),
        ),
    )

    assert projected == {
        "schemas": ["urn:test"],
        "id": "group-1",
        "displayName": "Finance",
        "meta": {"resourceType": "Group"},
    }


def test_empty_projection_parameters_preserve_default_resource_shape() -> None:
    selection = parse_attribute_selection(
        attributes="  ",
        excluded_attributes=None,
        allowed_attributes=ALLOWED,
    )
    payload = {
        "schemas": ["urn:test"],
        "id": "group-1",
        "displayName": "Finance",
        "members": [],
        "meta": {},
    }

    assert selection.attributes is None
    assert project_scim_resource(payload, selection=selection) == payload


@pytest.mark.parametrize(
    "parameter,value,match",
    [
        ("attributes", "displayName,,members", "empty attribute"),
        ("attributes", "members.value", "top-level"),
        ("excludedAttributes", "members[value eq \"x\"]", "top-level"),
        ("excludedAttributes", "unknown", "Unsupported"),
    ],
)
def test_attribute_selection_rejects_unsupported_projection_syntax(
    parameter: str,
    value: str,
    match: str,
) -> None:
    kwargs = {
        "attributes": value if parameter == "attributes" else None,
        "excluded_attributes": value if parameter == "excludedAttributes" else None,
        "allowed_attributes": ALLOWED,
    }

    with pytest.raises(InvalidScimRequest, match=match):
        parse_attribute_selection(**kwargs)
