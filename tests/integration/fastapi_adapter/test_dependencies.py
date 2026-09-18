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
    AccessGovernanceApplicationService,
    AuthorizationDecision,
    AuthorizationEngine,
    Permission,
    PermissionCode,
    ResourceDescriptor,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryConstraintRepository,
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
    InMemorySoDRuleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.integrations.fastapi import bearer_authentication, require_permission
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 1, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _build_app() -> tuple[
    TestClient,
    str,
    JwtTokenProvider,
    Session,
    InMemorySessionRepository,
]:
    clock = FrozenClock(NOW)
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()
    constraints = InMemoryConstraintRepository()
    sod = InMemorySoDRuleRepository()
    sessions = InMemorySessionRepository()

    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identities.save(identity)

    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    tenant.pull_events()
    tenant.activate(at=NOW)
    tenant.pull_events()
    tenants.save(tenant)

    membership = Membership.create(
        identity_id=identity.id,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    membership.pull_events()
    membership.activate(at=NOW)
    membership.pull_events()
    memberships.save(membership)

    permission = Permission(PermissionCode("invoice.read"), "Read invoices")
    permissions.save(permission)

    role = Role.create(
        name="Reader",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    role.add_permission(permission.code, at=NOW)
    role.pull_events()
    roles.save(role)

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
    )
    binding.pull_events()
    bindings.save(binding)

    governance = AccessGovernanceApplicationService(
        permission_repository=permissions,
        role_repository=roles,
        constraint_repository=constraints,
        sod_repository=sod,
        clock=clock,
        event_sink=InMemoryDomainEventSink(),
    )
    governance.register_minimum_assurance(
        str(permission.code),
        minimum_assurance=AssuranceLevel.AAL2,
        require_mfa=True,
        tenant_id=tenant.id,
    )

    engine = AuthorizationEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        clock=clock,
        constraint_repository=constraints,
        sod_repository=sod,
    )

    session = Session.open(
        identity_id=identity.id,
        context=AuthenticationContext(
            method=AuthenticationMethod.PASSKEY,
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    session.pull_events()
    sessions.save(session)

    token_provider = JwtTokenProvider(
        issuer="https://iam.example.com",
        audience="api://example",
        signing_key=token_bytes(32),
        session_repository=sessions,
        clock=clock,
        algorithm="HS256",
        leeway=timedelta(0),
    )
    token = token_provider.issue_access_token(session).token

    authenticate = bearer_authentication(token_provider)

    def resolve_tenant(_request: Request, _claims: AccessTokenClaims):
        return tenant.id

    allowed = require_permission(
        authentication=authenticate,
        authorization_engine=engine,
        permission=PermissionCode("invoice.read"),
        tenant_resolver=resolve_tenant,
    )
    denied = require_permission(
        authentication=authenticate,
        authorization_engine=engine,
        permission=PermissionCode("invoice.delete"),
        tenant_resolver=resolve_tenant,
    )

    def resolve_scope(
        _request: Request,
        _claims: AccessTokenClaims,
        _tenant_id,
    ):
        return TenantScope(tenant.id)

    def resolve_resource(
        _request: Request,
        _claims: AccessTokenClaims,
        _tenant_id,
    ):
        return ResourceDescriptor(
            resource_type="invoice",
            resource_id="inv-1",
            tenant_id=tenant.id,
        )

    def resolve_correlation(request: Request) -> str | None:
        return request.headers.get("x-correlation-id")

    contextual = require_permission(
        authentication=authenticate,
        authorization_engine=engine,
        permission=PermissionCode("invoice.read"),
        tenant_resolver=resolve_tenant,
        scope_resolver=resolve_scope,
        resource_resolver=resolve_resource,
        correlation_id_resolver=resolve_correlation,
    )

    app = FastAPI()

    @app.get("/me")
    def read_me(
        claims: Annotated[AccessTokenClaims, Depends(authenticate)],
    ) -> dict[str, str]:
        return {"subject": str(claims.subject_id)}

    @app.get("/invoices")
    def read_invoices(
        decision: Annotated[AuthorizationDecision, Depends(allowed)],
    ) -> dict[str, str]:
        return {"decision": str(decision.id)}

    @app.get("/forbidden")
    def forbidden(
        _decision: Annotated[AuthorizationDecision, Depends(denied)],
    ) -> dict[str, str]:
        return {"unexpected": "allow"}

    @app.get("/contextual")
    def contextual_route(
        decision: Annotated[AuthorizationDecision, Depends(contextual)],
    ) -> dict[str, str | None]:
        return {
            "resource": None if decision.resource is None else decision.resource.resource_id,
            "correlation": decision.correlation_id,
        }

    return TestClient(app), token, token_provider, session, sessions


def test_bearer_dependency_returns_401_without_credentials() -> None:
    client, _, _, _, _ = _build_app()

    response = client.get("/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_bearer_dependency_returns_401_for_invalid_token_without_leaking_reason() -> None:
    client, _, _, _, _ = _build_app()

    response = client.get("/me", headers={"Authorization": "Bearer invalid"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_valid_bearer_token_exposes_verified_subject() -> None:
    client, token, _, session, _ = _build_app()

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"subject": str(session.identity_id)}


def test_authorization_dependency_distinguishes_allow_and_forbidden() -> None:
    client, token, _, _, _ = _build_app()
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": "req-123"}

    allowed = client.get("/invoices", headers=headers)
    denied = client.get("/forbidden", headers=headers)

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Forbidden"}
    assert "www-authenticate" not in denied.headers


def test_custom_context_resolvers_feed_authorization_request() -> None:
    client, token, _, _, _ = _build_app()

    response = client.get(
        "/contextual",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Correlation-ID": "corr-42",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"resource": "inv-1", "correlation": "corr-42"}


def test_openapi_contains_bearer_security_scheme() -> None:
    client, _, _, _, _ = _build_app()

    schema = client.get("/openapi.json").json()

    assert schema["components"]["securitySchemes"]["PyIAMKitBearer"]["type"] == "http"
    assert schema["components"]["securitySchemes"]["PyIAMKitBearer"]["scheme"] == "bearer"


def test_session_revocation_turns_existing_token_into_401() -> None:
    client, token, _, session, sessions = _build_app()

    session.revoke(at=NOW + timedelta(minutes=1), reason="logout")
    session.pull_events()
    sessions.save(session)

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
