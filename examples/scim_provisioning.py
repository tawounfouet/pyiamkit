from datetime import UTC, datetime, timedelta

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    ProvisioningResourceId,
    ProvisioningSource,
    ScimEmail,
    ScimPatchOperation,
    ScimPatchVerb,
    ScimProvisioningService,
    ScimUserInput,
)
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


clock = MutableClock(datetime(2026, 9, 18, 8, 0, tzinfo=UTC))
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

scim = ScimProvisioningService(
    source=ProvisioningSource(
        source_id="example-scim",
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

created = scim.create_user(
    ScimUserInput(
        user_name="alice@example.com",
        external_id="hr-42",
        display_name="Alice Example",
        active=True,
        emails=(ScimEmail("alice@example.com", primary=True),),
    )
)

clock.value += timedelta(minutes=1)
suspended = scim.replace_user(
    ProvisioningResourceId.parse(created.id),
    ScimUserInput(
        user_name="alice@example.com",
        external_id="hr-42",
        display_name="Alice Example",
        active=False,
        emails=(ScimEmail("alice@example.com", primary=True),),
    ),
    if_match=created.meta.version,
)

clock.value += timedelta(minutes=1)
reactivated = scim.patch_user(
    ProvisioningResourceId.parse(created.id),
    (ScimPatchOperation(ScimPatchVerb.REPLACE, "active", True),),
    if_match=suspended.meta.version,
)

assert reactivated.user.active is True

clock.value += timedelta(minutes=1)
scim.delete_user(
    ProvisioningResourceId.parse(created.id),
    if_match=reactivated.meta.version,
)

print(
    "SCIM provisioning lifecycle OK:",
    created.id,
    created.meta.version,
    "->",
    reactivated.meta.version,
)
