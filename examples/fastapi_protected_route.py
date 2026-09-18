from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from pyiamkit.authentication import (
    AccessTokenClaims,
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Session,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.authorization import (
    AuthorizationDecision,
    AuthorizationEngine,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.integrations.fastapi import bearer_authentication, require_permission
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)

identities = InMemoryIdentityRepository()
tenants = InMemoryTenantRepository()
memberships = InMemoryMembershipRepository()
permissions = InMemoryPermissionCatalogRepository()
roles = InMemoryRoleRepository()
bindings = InMemoryRoleBindingRepository()
sessions = InMemorySessionRepository()

identity = Identity.create_user(display_name="Alice", created_at=now)
identity.pull_events()
identity.activate(at=now)
identity.pull_events()
identities.save(identity)

tenant = Tenant.create(name="ACME", slug="acme", created_at=now)
tenant.pull_events()
tenant.activate(at=now)
tenant.pull_events()
tenants.save(tenant)

membership = Membership.create(
    identity_id=identity.id,
    tenant_id=tenant.id,
    created_at=now,
)
membership.pull_events()
membership.activate(at=now)
membership.pull_events()
memberships.save(membership)

permission = Permission(PermissionCode("invoice.read"))
permissions.save(permission)

role = Role.create(
    name="Reader",
    role_type=RoleType.TENANT,
    tenant_id=tenant.id,
    created_at=now,
)
role.pull_events()
role.add_permission(permission.code, at=now)
role.pull_events()
roles.save(role)

binding = RoleBinding.create(
    identity_id=identity.id,
    role_id=role.id,
    tenant_id=tenant.id,
    scope=TenantScope(tenant.id),
    created_at=now,
)
binding.pull_events()
bindings.save(binding)

authorization = AuthorizationEngine(
    identity_repository=identities,
    tenant_repository=tenants,
    membership_repository=memberships,
    permission_repository=permissions,
    role_repository=roles,
    binding_repository=bindings,
    clock=clock,
)

session = Session.open(
    identity_id=identity.id,
    context=AuthenticationContext(
        method=AuthenticationMethod.PASSKEY,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        authenticated_at=now,
    ),
    created_at=now,
    expires_at=now + timedelta(hours=1),
)
session.pull_events()
sessions.save(session)

tokens = JwtTokenProvider(
    issuer="https://iam.example.com",
    audience="api://billing",
    signing_key=token_bytes(32),
    session_repository=sessions,
    clock=clock,
    algorithm="HS256",
)
access_token = tokens.issue_access_token(session).token

authenticate = bearer_authentication(tokens)


def resolve_tenant(_request: Request, _claims: AccessTokenClaims):
    return tenant.id


can_read_invoice = require_permission(
    authentication=authenticate,
    authorization_engine=authorization,
    permission=permission.code,
    tenant_resolver=resolve_tenant,
)

app = FastAPI()


@app.get("/invoices")
def invoices(
    decision: Annotated[AuthorizationDecision, Depends(can_read_invoice)],
) -> dict[str, str]:
    return {"decision": str(decision.id)}


client = TestClient(app)

authenticated = client.get(
    "/invoices",
    headers={"Authorization": f"Bearer {access_token}"},
)
anonymous = client.get("/invoices")

assert authenticated.status_code == 200
assert anonymous.status_code == 401

print("FastAPI protected route OK:", authenticated.status_code, anonymous.status_code)
