from datetime import UTC, datetime

import pytest

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import ProvisioningSource, ScimProvisioningService
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.provisioning.http import (
    SCIM_ERROR_SCHEMA,
    SCIM_MEDIA_TYPE,
    SCIM_PATCH_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimErrorType,
    ScimHttpTransport,
    parse_scim_patch_payload,
    parse_scim_user_payload,
    parse_user_filter,
)
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 9, 0, tzinfo=UTC)


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def _transport(*, max_results: int = 200) -> ScimHttpTransport:
    clock = FrozenClock()
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
            source_id="scim-http",
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
    return ScimHttpTransport(
        service,
        base_url="https://iam.example.com/scim/v2",
        max_results=max_results,
        documentation_uri="https://docs.example.com/scim",
    )


def _user_payload(
    *,
    user_name: str = "alice@example.com",
    external_id: str = "ext-42",
    active: bool = True,
) -> dict[str, object]:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": user_name,
        "externalId": external_id,
        "displayName": "Alice Example",
        "active": active,
        "name": {"givenName": "Alice", "familyName": "Example"},
        "emails": [{"value": user_name, "type": "work", "primary": True}],
    }


def test_discovery_endpoints_advertise_only_supported_capabilities() -> None:
    transport = _transport()

    config = transport.get_service_provider_config()
    resource_types = transport.get_resource_types()
    resource_type = transport.get_resource_type("User")
    schemas = transport.get_schemas()
    schema = transport.get_schema(SCIM_USER_SCHEMA)

    assert config.status == 200
    assert config.headers["Content-Type"] == SCIM_MEDIA_TYPE
    assert config.body is not None
    assert config.body["patch"] == {"supported": True}
    assert config.body["filter"] == {"supported": True, "maxResults": 200}
    assert config.body["bulk"]["supported"] is False  # type: ignore[index]
    assert config.body["changePassword"] == {"supported": False}
    assert config.body["sort"] == {"supported": False}
    assert config.body["etag"] == {"supported": True}
    assert config.body["documentationUri"] == "https://docs.example.com/scim"

    assert resource_types.body is not None
    assert resource_types.body["totalResults"] == 1
    assert resource_type.status == 200
    assert resource_type.body is not None
    assert resource_type.body["endpoint"] == "/Users"

    assert schemas.body is not None
    assert schemas.body["totalResults"] == 1
    assert schema.status == 200
    assert schema.body is not None
    assert schema.body["id"] == SCIM_USER_SCHEMA

    assert transport.get_resource_type("Group").status == 404
    assert transport.get_schema("urn:unknown").status == 404


def test_filter_parser_supports_only_user_name_and_external_id_equality() -> None:
    user_name = parse_user_filter('Username Eq "alice@example.com"')
    external_id = parse_user_filter('externalId eq "ext-42"')

    assert user_name is not None
    assert user_name.attribute == "userName"
    assert user_name.value == "alice@example.com"
    assert external_id is not None
    assert external_id.attribute == "externalId"
    assert parse_user_filter(None) is None
    assert parse_user_filter("   ") is None

    with pytest.raises(Exception, match="filter"):
        parse_user_filter('displayName eq "Alice"')


def test_payload_parsers_validate_schema_password_and_patch_shape() -> None:
    user = parse_scim_user_payload(_user_payload())
    assert user.user_name == "alice@example.com"
    assert user.primary_email == "alice@example.com"

    with pytest.raises(Exception, match="schemas"):
        parse_scim_user_payload({"userName": "alice"})
    with pytest.raises(Exception, match="password"):
        parse_scim_user_payload(
            {
                **_user_payload(),
                "password": "do-not-accept",
            }
        )

    operations = parse_scim_patch_payload(
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": False},
                {"op": "remove", "path": "displayName"},
            ],
        }
    )
    assert len(operations) == 2

    with pytest.raises(Exception, match="Operations"):
        parse_scim_patch_payload({"schemas": [SCIM_PATCH_SCHEMA], "Operations": []})
    with pytest.raises(Exception, match="op"):
        parse_scim_patch_payload(
            {
                "schemas": [SCIM_PATCH_SCHEMA],
                "Operations": [{"op": "merge", "path": "active", "value": True}],
            }
        )


def test_create_get_filter_replace_patch_and_delete_http_lifecycle() -> None:
    transport = _transport()

    created = transport.create_user(_user_payload())

    assert created.status == 201
    assert created.body is not None
    resource_id = str(created.body["id"])
    etag = created.headers["ETag"]
    assert created.headers["Content-Type"] == SCIM_MEDIA_TYPE
    assert created.headers["Location"].endswith(f"/Users/{resource_id}")

    fetched = transport.get_user(resource_id)
    assert fetched.status == 200
    assert fetched.headers["ETag"] == etag

    by_name = transport.list_users(
        filter_expression='userName eq "ALICE@EXAMPLE.COM"',
    )
    assert by_name.status == 200
    assert by_name.body is not None
    assert by_name.body["totalResults"] == 1

    by_external = transport.list_users(
        filter_expression='externalId eq "ext-42"',
    )
    assert by_external.body is not None
    assert by_external.body["totalResults"] == 1

    replaced = transport.replace_user(
        resource_id,
        _user_payload(
            user_name="alice2@example.com",
            external_id="ext-43",
            active=False,
        ),
        if_match=etag,
    )
    assert replaced.status == 200
    assert replaced.body is not None
    assert replaced.body["userName"] == "alice2@example.com"
    assert replaced.body["active"] is False
    replaced_etag = replaced.headers["ETag"]
    assert replaced_etag != etag

    patched = transport.patch_user(
        resource_id,
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "active", "value": True},
                {"op": "replace", "path": "displayName", "value": "Alice Reactivated"},
            ],
        },
        if_match=replaced_etag,
    )
    assert patched.status == 200
    assert patched.body is not None
    assert patched.body["active"] is True
    assert patched.body["displayName"] == "Alice Reactivated"

    deleted = transport.delete_user(
        resource_id,
        if_match=patched.headers["ETag"],
    )
    assert deleted.status == 204
    assert deleted.body is None
    assert transport.get_user(resource_id).status == 404


def test_transport_maps_scim_protocol_errors_without_internal_leakage() -> None:
    transport = _transport()
    created = transport.create_user(_user_payload())
    assert created.body is not None
    resource_id = str(created.body["id"])

    duplicate = transport.create_user(_user_payload())
    assert duplicate.status == 409
    assert duplicate.body is not None
    assert duplicate.body["schemas"] == [SCIM_ERROR_SCHEMA]
    assert duplicate.body["scimType"] == ScimErrorType.UNIQUENESS.value
    assert duplicate.body["status"] == "409"

    stale = transport.replace_user(
        resource_id,
        _user_payload(user_name="new@example.com", external_id="ext-new"),
        if_match='W/"stale"',
    )
    assert stale.status == 412

    invalid_filter = transport.list_users(filter_expression='displayName eq "Alice"')
    assert invalid_filter.status == 400
    assert invalid_filter.body is not None
    assert invalid_filter.body["scimType"] == ScimErrorType.INVALID_FILTER.value

    invalid_path = transport.patch_user(
        resource_id,
        {
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "groups", "value": []}],
        },
    )
    assert invalid_path.status == 400
    assert invalid_path.body is not None
    assert invalid_path.body["scimType"] == ScimErrorType.INVALID_PATH.value

    invalid_value = transport.create_user({"schemas": [SCIM_USER_SCHEMA]})
    assert invalid_value.status == 400
    assert invalid_value.body is not None
    assert invalid_value.body["scimType"] == ScimErrorType.INVALID_VALUE.value

    assert transport.get_user("not-a-uuid").status == 404
    assert transport.delete_user("not-a-uuid").status == 404


def test_list_pagination_caps_count_to_advertised_max_results() -> None:
    transport = _transport(max_results=1)
    transport.create_user(_user_payload(user_name="a@example.com", external_id="a"))
    transport.create_user(_user_payload(user_name="b@example.com", external_id="b"))

    response = transport.list_users(start_index=1, count=100)

    assert response.status == 200
    assert response.body is not None
    assert response.body["totalResults"] == 2
    assert response.body["itemsPerPage"] == 1

    invalid_start = transport.list_users(start_index=0)
    assert invalid_start.status == 400
    assert invalid_start.body is not None
    assert invalid_start.body["scimType"] == ScimErrorType.INVALID_VALUE.value
