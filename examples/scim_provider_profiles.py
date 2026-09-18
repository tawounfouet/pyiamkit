from datetime import UTC, datetime

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    MICROSOFT_ENTRA_PROFILE,
    OKTA_SCIM_PROFILE,
    ProvisioningSource,
    ScimHttpTransport,
    ScimProvisioningService,
)
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 18, 11, 0, tzinfo=UTC)


def build_transport(profile):
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
    tenant = tenancy_service.create_tenant(name="ACME", slug=f"acme-{profile.kind.value}")
    tenant = tenancy_service.activate_tenant(tenant.id)

    provisioning = ScimProvisioningService(
        source=ProvisioningSource(
            source_id=f"{profile.kind.value}-example",
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
    return ScimHttpTransport(
        provisioning,
        base_url="https://iam.example.com/scim/v2",
        provider_profile=profile,
    )


entra = build_transport(MICROSOFT_ENTRA_PROFILE)
created = entra.create_user(
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice@example.com",
        "externalId": "ext-42",
        "active": True,
    }
)
assert created.status == 201
assert entra.list_users(filter_expression="externalId eq ext-42").body["totalResults"] == 1

okta = build_transport(OKTA_SCIM_PROFILE)
created_okta = okta.create_user(
    {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bob@example.com",
        "externalId": "ext-99",
        "active": True,
    }
)
assert created_okta.status == 201
assert (
    okta.list_users(filter_expression='userName eq "bob@example.com"').body["totalResults"]
    == 1
)

print("SCIM provider profiles OK: Entra + Okta")
