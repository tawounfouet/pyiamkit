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
from pyiamkit.provisioning import (
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

NOW = datetime(2026, 9, 18, 12, 30, tzinfo=UTC)


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def _client() -> TestClient:
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
    tenant = tenancy_service.create_tenant(name="ACME", slug="acme-groups")
    tenant = tenancy_service.activate_tenant(tenant.id)
    source = ProvisioningSource(
        source_id="fastapi-groups",
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
    transport = ScimHttpTransport(
        user_service,
        base_url="https://iam.example.com/scim/v2",
        group_service=group_service,
    )

    def require_access(
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        if authorization != "Bearer scim-groups-token":
            raise HTTPException(status_code=401, detail="Not authenticated")
        return authorization

    app = FastAPI()
    app.include_router(
        create_scim_router(
            transport=transport,
            access_dependency=require_access,
            prefix="/scim/v2",
        )
    )
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"Authorization": "Bearer scim-groups-token"}


def test_group_routes_are_protected_and_present_in_openapi() -> None:
    client = _client()

    denied = client.get("/scim/v2/Groups")
    schema = client.get("/openapi.json").json()

    assert denied.status_code == 401
    assert "/scim/v2/Groups" in schema["paths"]
    assert "/scim/v2/Groups/{resource_id}" in schema["paths"]


def test_fastapi_scim_group_lifecycle() -> None:
    client = _client()

    user = client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={
            "schemas": [SCIM_USER_SCHEMA],
            "userName": "alice@example.com",
            "externalId": "alice-ext",
            "active": True,
        },
    )
    assert user.status_code == 201
    user_id = user.json()["id"]

    created = client.post(
        "/scim/v2/Groups",
        headers=_headers(),
        json={
            "schemas": [SCIM_GROUP_SCHEMA],
            "displayName": "Finance",
            "externalId": "finance-ext",
            "members": [{"value": user_id}],
        },
    )
    assert created.status_code == 201
    assert created.headers["content-type"].startswith("application/scim+json")
    group_id = created.json()["id"]

    filtered = client.get(
        "/scim/v2/Groups",
        headers=_headers(),
        params={"filter": 'displayName eq "finance"'},
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1

    patched = client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers={**_headers(), "If-Match": created.headers["etag"]},
        json={
            "schemas": [SCIM_PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "replace",
                    "value": {"displayName": "Finance Team"},
                }
            ],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["displayName"] == "Finance Team"

    deleted = client.delete(
        f"/scim/v2/Groups/{group_id}",
        headers={**_headers(), "If-Match": patched.headers["etag"]},
    )
    assert deleted.status_code == 204

    user_still_exists = client.get(
        f"/scim/v2/Users/{user_id}",
        headers=_headers(),
    )
    assert user_still_exists.status_code == 200
