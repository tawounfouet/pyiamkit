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
    ScimProviderProfile,
    ScimProvisioningService,
)
from pyiamkit.provisioning.adapters import (
    InMemoryProvisioningGroupRepository,
    InMemoryProvisioningUserRepository,
)
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 19, 8, 0, tzinfo=UTC)
SCIM_TOKEN = "Bearer qualification-scim-token"


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def build_client(profile: ScimProviderProfile, *, source_id: str) -> TestClient:
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
    tenant = tenancy_service.create_tenant(
        name=f"{profile.kind.value} qualification",
        slug=f"qualification-{profile.kind.value.replace('_', '-')}",
    )
    tenant = tenancy_service.activate_tenant(tenant.id)
    source = ProvisioningSource(
        source_id=source_id,
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
        provider_profile=profile,
        group_service=group_service,
    )

    def require_access(
        authorization: Annotated[str | None, Header()] = None,
    ) -> str:
        if authorization != SCIM_TOKEN:
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


def headers() -> dict[str, str]:
    return {"Authorization": SCIM_TOKEN}
