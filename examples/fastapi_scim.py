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
from pyiamkit.provisioning import ProvisioningSource, ScimHttpTransport, ScimProvisioningService
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 18, 10, 0, tzinfo=UTC)


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
        source_id="example-http-scim",
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


def require_access(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if authorization != "Bearer example-scim-token":
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

client = TestClient(app)
headers = {"Authorization": "Bearer example-scim-token"}

created = client.post(
    "/scim/v2/Users",
    headers=headers,
    json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice@example.com",
        "externalId": "hr-42",
        "displayName": "Alice Example",
        "active": True,
        "emails": [{"value": "alice@example.com", "primary": True}],
    },
)

assert created.status_code == 201
assert created.headers["content-type"].startswith("application/scim+json")
assert "etag" in created.headers
print("FastAPI SCIM HTTP integration OK:", created.status_code, created.json()["id"])
