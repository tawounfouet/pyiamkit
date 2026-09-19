from datetime import UTC, datetime

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import (
    ProvisioningSource,
    ScimGroupInput,
    ScimGroupMember,
    ScimGroupProvisioningService,
    ScimProvisioningService,
    ScimUserInput,
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


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 18, 13, 0, tzinfo=UTC)


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
tenant = tenancy_service.create_tenant(name="ACME", slug="acme-groups-example")
tenant = tenancy_service.activate_tenant(tenant.id)
source = ProvisioningSource(
    source_id="groups-example",
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

alice = user_service.create_user(
    ScimUserInput(
        user_name="alice@example.com",
        display_name="Alice",
    )
)
group = group_service.create_group(
    ScimGroupInput(
        display_name="Engineering",
        external_id="group-42",
        members=(ScimGroupMember(alice.id),),
    )
)

assert group.group.members[0].value == alice.id
assert "/Users/" in (group.group.members[0].ref or "")
print("SCIM Group provisioning OK:", group.id, group.group.display_name)
