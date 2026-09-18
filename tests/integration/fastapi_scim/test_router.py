from datetime import UTC, datetime
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.integrations.fastapi_scim import create_scim_router
from pyiamkit.provisioning import ProvisioningSource, ScimProvisioningService
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.provisioning.http import (
    SCIM_MEDIA_TYPE,
    SCIM_PATCH_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimHttpTransport,
)
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 9, 30, tzinfo=UTC)


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def _client() -> TestClient:
    clock = FrozenClock()
    events = InMemoryDomainEventSink()
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()

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

    provisioning = ScimProvisioningService(
        source=ProvisioningSource(
            source_id="fastapi-scim",
            tenant_id=tenant.id,
            base_url="https://iam.example.com/scim/v2",
        ),
        identity_service=identity_service,
        identity_repository=identities,
        tenancy_service=tenancy_service,
        membership_repository=memberships,
        resource_repository=InMemoryProvisioningUserRepository(),
        clock=clock,
        event_sink=events,
    )
    transport = ScimHttpTransport(
        provisioning,
        base_url="https://iam.example.com/scim/v2",
    )

    def require_scim_access(
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        if authorization != "Bearer scim-admin-token":
            raise HTTPException(status_code=401, detail="Not authenticated")
        return authorization

    app = FastAPI()
    app.include_router(
        create_scim_router(
            transport=transport,
            access_dependency=require_scim_access,
            prefix="/scim/v2",
        )
    )
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer scim-admin-token"}


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
        "emails": [{"value": user_name, "primary": True}],
    }


def test_scim_router_requires_explicit_access_dependency() -> None:
    client = _client()

    response = client.get("/scim/v2/ServiceProviderConfig")

    assert response.status_code == 401


def test_scim_discovery_endpoints_use_scim_media_type() -> None:
    client = _client()

    config = client.get("/scim/v2/ServiceProviderConfig", headers=_headers())
    resource_types = client.get("/scim/v2/ResourceTypes", headers=_headers())
    resource_type = client.get("/scim/v2/ResourceTypes/User", headers=_headers())
    schemas = client.get("/scim/v2/Schemas", headers=_headers())
    schema = client.get(
        f"/scim/v2/Schemas/{SCIM_USER_SCHEMA}",
        headers=_headers(),
    )

    for response in (config, resource_types, resource_type, schemas, schema):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(SCIM_MEDIA_TYPE)

    assert config.json()["patch"]["supported"] is True
    assert resource_type.json()["endpoint"] == "/Users"
    assert schema.json()["id"] == SCIM_USER_SCHEMA


def test_scim_fastapi_user_lifecycle_and_conditional_requests() -> None:
    client = _client()

    created = client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(),
    )

    assert created.status_code == 201
    assert created.headers["content-type"].startswith(SCIM_MEDIA_TYPE)
    resource_id = created.json()["id"]
    etag = created.headers["etag"]
    assert created.headers["location"].endswith(f"/Users/{resource_id}")

    fetched = client.get(
        f"/scim/v2/Users/{resource_id}",
        headers=_headers(),
    )
    assert fetched.status_code == 200
    assert fetched.headers["etag"] == etag

    filtered = client.get(
        "/scim/v2/Users",
        headers=_headers(),
        params={"filter": 'userName eq "ALICE@EXAMPLE.COM"'},
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1

    stale = client.put(
        f"/scim/v2/Users/{resource_id}",
        headers={**_headers(), "If-Match": 'W/"stale"'},
        json=_user_payload(user_name="alice2@example.com", external_id="ext-43"),
    )
    assert stale.status_code == 412
    assert stale.json()["status"] == "412"

    replaced = client.put(
        f"/scim/v2/Users/{resource_id}",
        headers={**_headers(), "If-Match": etag},
        json=_user_payload(
            user_name="alice2@example.com",
            external_id="ext-43",
            active=False,
        ),
    )
    assert replaced.status_code == 200
    assert replaced.json()["active"] is False

    patched = client.patch(
        f"/scim/v2/Users/{resource_id}",
        headers={**_headers(), "If-Match": replaced.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [{"op": "replace", "path": "active", "value": True}],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["active"] is True

    deleted = client.delete(
        f"/scim/v2/Users/{resource_id}",
        headers={**_headers(), "If-Match": patched.headers["etag"]},
    )
    assert deleted.status_code == 204
    assert deleted.content == b""


def test_scim_fastapi_maps_uniqueness_and_invalid_filter_errors() -> None:
    client = _client()
    first = client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(),
    )
    assert first.status_code == 201

    duplicate = client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json=_user_payload(),
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["scimType"] == "uniqueness"

    invalid_filter = client.get(
        "/scim/v2/Users",
        headers=_headers(),
        params={"filter": 'displayName eq "Alice"'},
    )
    assert invalid_filter.status_code == 400
    assert invalid_filter.json()["scimType"] == "invalidFilter"
