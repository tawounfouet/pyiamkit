from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.identity import IdentityId
from pyiamkit.provisioning import (
    InvalidProvisioningResource,
    InvalidScimRequest,
    ProvisioningManagedStateConflict,
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
    ScimGroupInput,
    ScimGroupMember,
    ScimGroupPatchOperation,
    ScimPatchVerb,
    UnsupportedScimPatch,
)
from pyiamkit.provisioning.group_domain import ProvisioningGroup
from pyiamkit.provisioning.group_http import (
    group_resource_type_resource,
    group_schema_resource,
    parse_group_filter,
    parse_scim_group_patch_payload,
    parse_scim_group_payload,
)
from pyiamkit.provisioning.group_scim import (
    SCIM_GROUP_SCHEMA,
    ScimGroupListResponse,
    ScimGroupResource,
    group_member_ref,
    group_resource_location,
    require_group_patch_schema,
)
from pyiamkit.provisioning.scim import SCIM_PATCH_SCHEMA, ScimMeta
from pyiamkit.provisioning.providers import MICROSOFT_ENTRA_PROFILE
from pyiamkit.tenancy import MembershipId, TenantId

NOW = datetime(2026, 9, 18, 12, 30, tzinfo=UTC)


def _group(*, members: tuple[ProvisioningResourceId, ...] = ()) -> ProvisioningGroup:
    return ProvisioningGroup.create(
        source_id="group-scim",
        tenant_id=TenantId.new(),
        display_name="Finance",
        member_ids=members,
        created_at=NOW,
        external_id="group-42",
    )


def test_group_domain_validates_constructor_invariants() -> None:
    ids = {
        "resource_id": ProvisioningResourceId.new(),
        "tenant_id": TenantId.new(),
    }

    with pytest.raises(InvalidProvisioningResource, match="source_id"):
        ProvisioningGroup._rehydrate(
            **ids,
            version=0,
            source_id=" ",
            display_name="Finance",
            member_ids=(),
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="display_name"):
        ProvisioningGroup._rehydrate(
            **ids,
            version=0,
            source_id="source",
            display_name=" ",
            member_ids=(),
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="version"):
        ProvisioningGroup._rehydrate(
            **ids,
            version=-1,
            source_id="source",
            display_name="Finance",
            member_ids=(),
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="deleted_at"):
        ProvisioningGroup._rehydrate(
            **ids,
            version=1,
            source_id="source",
            display_name="Finance",
            member_ids=(),
            status=ProvisioningResourceStatus.DELETED,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="UTC-aware"):
        ProvisioningGroup.create(
            source_id="source",
            tenant_id=ids["tenant_id"],
            display_name="Finance",
            member_ids=(),
            created_at=datetime(2026, 9, 18, 12, 30),
        )


def test_group_domain_noops_idempotence_and_immutability() -> None:
    member = ProvisioningResourceId.new()
    group = _group(members=(member,))
    initial_version = group.version

    group.add_members((member,), at=NOW + timedelta(minutes=1))
    group.remove_members((ProvisioningResourceId.new(),), at=NOW + timedelta(minutes=2))
    group.replace_members((member,), at=NOW + timedelta(minutes=3))
    group.rename("Finance", at=NOW + timedelta(minutes=4))
    group.set_external_id("group-42", at=NOW + timedelta(minutes=5))
    assert group.version == initial_version

    group.set_external_id("   ", at=NOW + timedelta(minutes=6))
    assert group.external_id is None
    assert group.version == initial_version + 1

    group.delete(at=NOW + timedelta(minutes=7))
    deleted_version = group.version
    group.delete(at=NOW + timedelta(minutes=8))
    assert group.version == deleted_version
    assert group.member_ids == ()

    with pytest.raises(ProvisioningManagedStateConflict, match="immutable"):
        group.rename("Other", at=NOW + timedelta(minutes=9))
    assert hash(group) == hash(group.id)
    assert group.__eq__(object()) is NotImplemented


def test_group_scim_value_objects_and_serialization_edges() -> None:
    member = ScimGroupMember(
        value=" user-1 ",
        display=" Alice ",
        ref=" https://example.test/Users/user-1 ",
    )
    assert member.value == "user-1"
    assert member.display == "Alice"
    assert member.ref == "https://example.test/Users/user-1"
    assert member.to_dict() == {
        "value": "user-1",
        "display": "Alice",
        "$ref": "https://example.test/Users/user-1",
    }

    sparse = ScimGroupMember("user-2")
    assert sparse.to_dict() == {"value": "user-2"}
    with pytest.raises(InvalidScimRequest, match="must not be empty"):
        ScimGroupMember(" ")

    with pytest.raises(InvalidScimRequest, match="unique"):
        ScimGroupInput(
            display_name="Finance",
            members=(ScimGroupMember("u1"), ScimGroupMember("u1")),
        )

    group = ScimGroupInput(
        display_name=" Finance ",
        external_id=" ",
        members=(sparse,),
    )
    assert group.display_name == "Finance"
    assert group.external_id is None

    meta = ScimMeta(
        resource_type="Group",
        created=NOW,
        last_modified=NOW,
        version='W/"1"',
    )
    resource = ScimGroupResource(id="g1", group=group, meta=meta)
    payload = resource.to_dict()
    assert payload["displayName"] == "Finance"
    assert "externalId" not in payload

    listing = ScimGroupListResponse(
        total_results=1,
        start_index=1,
        items_per_page=1,
        resources=(resource,),
    ).to_dict()
    assert listing["totalResults"] == 1
    assert listing["Resources"] == [payload]

    operation = ScimGroupPatchOperation(ScimPatchVerb.REPLACE, "   ", {"displayName": "X"})
    assert operation.path is None

    assert group_resource_location(None, "g1") is None
    assert group_member_ref(None, "u1") is None
    with pytest.raises(InvalidScimRequest, match="schemas"):
        require_group_patch_schema([])


def test_group_payload_parser_rejects_malformed_inputs() -> None:
    valid = {
        "schemas": [SCIM_GROUP_SCHEMA],
        "displayName": "Finance",
        "members": [{"value": "u1", "display": "Alice", "$ref": "https://x/Users/u1"}],
    }
    parsed = parse_scim_group_payload(valid)
    assert parsed.display_name == "Finance"
    assert parsed.members[0].ref == "https://x/Users/u1"

    with pytest.raises(InvalidScimRequest, match="JSON object"):
        parse_scim_group_payload([])
    with pytest.raises(InvalidScimRequest, match="schemas"):
        parse_scim_group_payload({"displayName": "Finance"})
    with pytest.raises(InvalidScimRequest, match="displayName"):
        parse_scim_group_payload({"schemas": [SCIM_GROUP_SCHEMA], "displayName": " "})
    with pytest.raises(InvalidScimRequest, match="externalId"):
        parse_scim_group_payload(
            {"schemas": [SCIM_GROUP_SCHEMA], "displayName": "Finance", "externalId": 7}
        )
    with pytest.raises(InvalidScimRequest, match="members must be an array"):
        parse_scim_group_payload(
            {"schemas": [SCIM_GROUP_SCHEMA], "displayName": "Finance", "members": "bad"}
        )
    with pytest.raises(InvalidScimRequest, match="JSON object"):
        parse_scim_group_payload(
            {"schemas": [SCIM_GROUP_SCHEMA], "displayName": "Finance", "members": [1]}
        )
    with pytest.raises(InvalidScimRequest, match="member value"):
        parse_scim_group_payload(
            {"schemas": [SCIM_GROUP_SCHEMA], "displayName": "Finance", "members": [{}]}
        )
    with pytest.raises(InvalidScimRequest, match="member display"):
        parse_scim_group_payload(
            {
                "schemas": [SCIM_GROUP_SCHEMA],
                "displayName": "Finance",
                "members": [{"value": "u1", "display": 7}],
            }
        )
    with pytest.raises(InvalidScimRequest, match=r"member $ref"):
        parse_scim_group_payload(
            {
                "schemas": [SCIM_GROUP_SCHEMA],
                "displayName": "Finance",
                "members": [{"value": "u1", "$ref": 7}],
            }
        )


def test_group_patch_parser_rejects_malformed_operations() -> None:
    valid = parse_scim_group_patch_payload(
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "operations": [{"op": "replace", "path": "displayName", "value": "Finance"}],
        }
    )
    assert valid[0].op is ScimPatchVerb.REPLACE

    with pytest.raises(InvalidScimRequest, match="schemas"):
        parse_scim_group_patch_payload({"Operations": []})
    with pytest.raises(InvalidScimRequest, match="non-empty array"):
        parse_scim_group_patch_payload({"schemas": [SCIM_PATCH_SCHEMA], "Operations": []})
    with pytest.raises(InvalidScimRequest, match="JSON object"):
        parse_scim_group_patch_payload(
            {"schemas": [SCIM_PATCH_SCHEMA], "Operations": [1]}
        )
    with pytest.raises(InvalidScimRequest, match="op must be a string"):
        parse_scim_group_patch_payload(
            {"schemas": [SCIM_PATCH_SCHEMA], "Operations": [{"op": 7}]}
        )
    with pytest.raises(InvalidScimRequest, match="path must be a string"):
        parse_scim_group_patch_payload(
            {"schemas": [SCIM_PATCH_SCHEMA], "Operations": [{"op": "replace", "path": 7}]}
        )
    with pytest.raises(InvalidScimRequest, match="Unsupported"):
        parse_scim_group_patch_payload(
            {"schemas": [SCIM_PATCH_SCHEMA], "Operations": [{"op": "merge"}]}
        )


def test_group_filter_and_discovery_edge_cases() -> None:
    assert parse_group_filter(None) is None
    assert parse_group_filter("   ") is None
    assert parse_group_filter('DisplayName EQ "Finance"') == ("displayName", "Finance")
    assert parse_group_filter("externalId eq group-42", profile=MICROSOFT_ENTRA_PROFILE) == (
        "externalId",
        "group-42",
    )

    with pytest.raises(InvalidScimRequest, match="Unsupported"):
        parse_group_filter('members eq "u1"')
    with pytest.raises(InvalidScimRequest, match="Malformed"):
        parse_group_filter('displayName eq "Finance')
    with pytest.raises(InvalidScimRequest, match="requires quoted"):
        parse_group_filter("externalId eq group-42")
    with pytest.raises(InvalidScimRequest, match="non-empty tokens"):
        parse_group_filter("externalId eq two words", profile=MICROSOFT_ENTRA_PROFILE)

    resource_type = group_resource_type_resource(None)
    schema = group_schema_resource(None)
    assert "meta" not in resource_type
    assert "meta" not in schema
    assert resource_type["endpoint"] == "/Groups"
    assert schema["id"] == SCIM_GROUP_SCHEMA
