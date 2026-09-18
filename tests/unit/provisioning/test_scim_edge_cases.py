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
    ScimEmail,
    ScimListResponse,
    ScimMeta,
    ScimName,
    ScimPatchOperation,
    ScimPatchVerb,
    ScimUserInput,
    ScimUserResource,
    UnsupportedScimPatch,
    apply_user_patch,
)
from pyiamkit.provisioning.scim import resource_location
from pyiamkit.tenancy import MembershipId, TenantId

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


def _base_user() -> ScimUserInput:
    return ScimUserInput(
        user_name=" alice@example.com ",
        display_name=" Alice ",
        external_id=" ext-42 ",
        name=ScimName(given_name=" Alice ", family_name=" Example "),
        emails=(ScimEmail(" alice@example.com ", primary=True),),
    )


def _resource() -> ProvisioningUser:
    return ProvisioningUser.create(
        source_id="source",
        identity_id=IdentityId.new(),
        tenant_id=TenantId.new(),
        membership_id=MembershipId.new(),
        user_name="alice@example.com",
        external_id="ext-42",
        active=True,
        created_at=NOW,
    )


def test_scim_value_objects_normalize_and_validate_input() -> None:
    user = _base_user()

    assert user.user_name == "alice@example.com"
    assert user.display_name == "Alice"
    assert user.external_id == "ext-42"
    assert user.name == ScimName(given_name="Alice", family_name="Example")
    assert user.primary_email == "alice@example.com"
    assert user.effective_display_name == "Alice"

    fallback = ScimUserInput(
        user_name="fallback",
        emails=(ScimEmail("first@example.com"),),
    )
    assert fallback.primary_email == "first@example.com"
    assert fallback.effective_display_name == "fallback"

    empty = ScimUserInput(user_name="empty")
    assert empty.primary_email is None

    with pytest.raises(InvalidScimRequest, match="userName"):
        ScimUserInput(user_name="   ")
    with pytest.raises(InvalidScimRequest, match="at most one primary"):
        ScimUserInput(
            user_name="duplicate-primary",
            emails=(
                ScimEmail("a@example.com", primary=True),
                ScimEmail("b@example.com", primary=True),
            ),
        )
    with pytest.raises(InvalidScimRequest, match="email value"):
        ScimEmail("   ")


def test_scim_resource_and_list_serialization_cover_optional_shapes() -> None:
    user = _base_user()
    meta = ScimMeta(
        resource_type="User",
        created=NOW,
        last_modified=NOW + timedelta(minutes=1),
        version='W/"1"',
        location="https://iam.example.com/scim/v2/Users/1",
    )
    resource = ScimUserResource(id="1", user=user, meta=meta)

    payload = resource.to_dict()

    assert payload["schemas"]
    assert payload["externalId"] == "ext-42"
    assert payload["displayName"] == "Alice"
    assert payload["name"] == {"givenName": "Alice", "familyName": "Example"}
    assert payload["emails"] == [{"value": "alice@example.com", "type": "work", "primary": True}]
    assert payload["meta"]["created"].endswith("Z")  # type: ignore[index]
    assert payload["meta"]["location"] == meta.location  # type: ignore[index]

    sparse = ScimUserResource(
        id="2",
        user=ScimUserInput(user_name="sparse"),
        meta=ScimMeta(
            resource_type="User",
            created=NOW,
            last_modified=NOW,
            version='W/"2"',
        ),
    ).to_dict()
    assert "externalId" not in sparse
    assert "displayName" not in sparse
    assert "name" not in sparse
    assert "emails" not in sparse
    assert "location" not in sparse["meta"]  # type: ignore[operator]

    listed = ScimListResponse(
        total_results=1,
        start_index=1,
        items_per_page=1,
        resources=(resource,),
    ).to_dict()
    assert listed["totalResults"] == 1
    assert listed["Resources"] == [payload]


def test_scim_patch_supports_replace_add_and_remove_variants() -> None:
    current = _base_user()
    patched = apply_user_patch(
        current,
        (
            ScimPatchOperation(ScimPatchVerb.REPLACE, "userName", "new@example.com"),
            ScimPatchOperation(ScimPatchVerb.REMOVE, "displayName"),
            ScimPatchOperation(ScimPatchVerb.REMOVE, "externalId"),
            ScimPatchOperation(ScimPatchVerb.REPLACE, "name.givenName", "Alicia"),
            ScimPatchOperation(ScimPatchVerb.REMOVE, "name.familyName"),
            ScimPatchOperation(ScimPatchVerb.REMOVE, "emails"),
        ),
    )

    assert patched.user_name == "new@example.com"
    assert patched.display_name is None
    assert patched.external_id is None
    assert patched.name.given_name == "Alicia"
    assert patched.name.family_name is None
    assert patched.emails == ()

    added = apply_user_patch(
        patched,
        (
            ScimPatchOperation(ScimPatchVerb.ADD, "displayName", "Alicia"),
            ScimPatchOperation(ScimPatchVerb.ADD, "externalId", "ext-new"),
            ScimPatchOperation(ScimPatchVerb.ADD, "name.familyName", "Example"),
        ),
    )
    assert added.display_name == "Alicia"
    assert added.external_id == "ext-new"
    assert added.name.family_name == "Example"


@pytest.mark.parametrize(
    "operation, message",
    [
        (ScimPatchOperation(ScimPatchVerb.REMOVE, "active"), "active"),
        (ScimPatchOperation(ScimPatchVerb.REPLACE, "active", "yes"), "boolean"),
        (ScimPatchOperation(ScimPatchVerb.REMOVE, "userName"), "userName"),
        (ScimPatchOperation(ScimPatchVerb.REPLACE, "userName", ""), "non-empty"),
        (ScimPatchOperation(ScimPatchVerb.REPLACE, "unknown", "x"), "Unsupported"),
    ],
)
def test_scim_patch_rejects_invalid_scalar_operations(
    operation: ScimPatchOperation,
    message: str,
) -> None:
    error = (
        UnsupportedScimPatch
        if operation.path in {"active", "userName", "unknown"}
        and (operation.op is ScimPatchVerb.REMOVE or operation.path == "unknown")
        else InvalidScimRequest
    )
    with pytest.raises(error, match=message):
        apply_user_patch(_base_user(), (operation,))


@pytest.mark.parametrize(
    "value, message",
    [
        ("not-a-list", "must be a list"),
        ([1], "entries must be objects"),
        ([{"value": 123}], "value must be a string"),
        ([{"value": "a@example.com", "type": 7}], "type must be a string"),
        ([{"value": "a@example.com", "primary": "yes"}], "primary must be boolean"),
    ],
)
def test_scim_patch_validates_email_collection(value: object, message: str) -> None:
    with pytest.raises(InvalidScimRequest, match=message):
        apply_user_patch(
            _base_user(),
            (ScimPatchOperation(ScimPatchVerb.REPLACE, "emails", value),),
        )


def test_scim_patch_operation_and_resource_location_validation() -> None:
    with pytest.raises(InvalidScimRequest, match="path"):
        ScimPatchOperation(ScimPatchVerb.REPLACE, "   ", "x")

    assert resource_location(None, "1") is None
    assert (
        resource_location("https://iam.example.com/scim/v2", "1")
        == "https://iam.example.com/scim/v2/Users/1"
    )


def test_provisioning_resource_validates_state_and_time_invariants() -> None:
    ids = {
        "resource_id": ProvisioningResourceId.new(),
        "identity_id": IdentityId.new(),
        "tenant_id": TenantId.new(),
        "membership_id": MembershipId.new(),
    }

    with pytest.raises(InvalidProvisioningResource, match="source_id"):
        ProvisioningUser._rehydrate(
            **ids,
            version=0,
            source_id=" ",
            user_name="alice",
            active=True,
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="user_name"):
        ProvisioningUser._rehydrate(
            **ids,
            version=0,
            source_id="source",
            user_name=" ",
            active=True,
            status=ProvisioningResourceStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="deleted_at"):
        ProvisioningUser._rehydrate(
            **ids,
            version=1,
            source_id="source",
            user_name="alice",
            active=False,
            status=ProvisioningResourceStatus.DELETED,
            created_at=NOW,
            updated_at=NOW,
            external_id=None,
            deleted_at=None,
        )
    with pytest.raises(InvalidProvisioningResource, match="UTC-aware"):
        ProvisioningUser.create(
            source_id="source",
            identity_id=ids["identity_id"],
            tenant_id=ids["tenant_id"],
            membership_id=ids["membership_id"],
            user_name="alice",
            active=True,
            created_at=datetime(2026, 9, 18, 8, 0),
        )


def test_provisioning_resource_replace_delete_equality_and_hash_contract() -> None:
    resource = _resource()
    other = _resource()

    resource.replace(
        user_name=" alice2@example.com ",
        external_id=" ",
        active=False,
        at=NOW + timedelta(minutes=1),
    )
    assert resource.user_name == "alice2@example.com"
    assert resource.external_id is None
    assert resource.active is False
    assert resource.version == 1

    with pytest.raises(InvalidProvisioningResource, match="user_name"):
        resource.replace(
            user_name=" ",
            external_id=None,
            active=True,
            at=NOW + timedelta(minutes=2),
        )

    resource.delete(at=NOW + timedelta(minutes=2))
    deleted_version = resource.version
    resource.delete(at=NOW + timedelta(minutes=3))
    assert resource.version == deleted_version
    assert resource.deleted_at == NOW + timedelta(minutes=2)
    assert hash(resource) == hash(resource.id)
    assert resource != other
    assert resource.__eq__(object()) is NotImplemented

    with pytest.raises(ProvisioningManagedStateConflict, match="immutable"):
        resource.replace(
            user_name="again",
            external_id=None,
            active=True,
            at=NOW + timedelta(minutes=4),
        )
