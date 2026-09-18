import json
from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import django
import pytest
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Session,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.authorization import (
    AccessGovernanceApplicationService,
    AuthorizationEngine,
    Permission,
    PermissionCode,
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
from pyiamkit.integrations.django import (
    PyIAMKitAuthenticationMiddleware,
    bearer_required,
    get_authenticated_claims,
    get_authorization_decision,
    permission_required,
)
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

if not settings.configured:
    settings.configure(
        SECRET_KEY="pyiamkit-django-tests",
        DEFAULT_CHARSET="utf-8",
        ALLOWED_HOSTS=["testserver"],
        USE_TZ=True,
    )
    django.setup()

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _stack(
    *,
    assurance_level: AssuranceLevel = AssuranceLevel.AAL2,
    mfa: bool = True,
):
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

    authorization = AuthorizationEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        constraint_repository=constraints,
        sod_repository=sod,
        clock=clock,
    )

    session = Session.open(
        identity_id=identity.id,
        context=AuthenticationContext(
            method=AuthenticationMethod.PASSWORD,
            assurance_level=assurance_level,
            mfa=mfa,
            authenticated_at=NOW,
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    session.pull_events()
    sessions.save(session)

    token_provider = JwtTokenProvider(
        issuer="https://iam.example.com",
        audience="api://django",
        signing_key=token_bytes(32),
        session_repository=sessions,
        clock=clock,
        algorithm="HS256",
        leeway=timedelta(0),
    )
    token = token_provider.issue_access_token(session).token

    def resolve_tenant(_request: HttpRequest, _claims):
        return tenant.id

    return token_provider, token, authorization, permission, tenant, resolve_tenant


def _json(response: HttpResponse) -> object:
    return json.loads(response.content.decode("utf-8"))


def test_bearer_required_returns_401_and_www_authenticate_when_missing() -> None:
    token_provider, _, _, _, _, _ = _stack()

    @bearer_required(token_provider)
    def protected(_request: HttpRequest) -> HttpResponse:
        return JsonResponse({"ok": True})

    response = protected(RequestFactory().get("/protected"))

    assert response.status_code == 401
    assert response["WWW-Authenticate"] == "Bearer"
    assert _json(response) == {"detail": "Not authenticated"}


def test_bearer_required_attaches_verified_claims() -> None:
    token_provider, token, _, _, _, _ = _stack()

    @bearer_required(token_provider)
    def protected(request: HttpRequest) -> HttpResponse:
        claims = get_authenticated_claims(request)
        assert claims is not None
        return JsonResponse({"subject": str(claims.subject_id)})

    request = RequestFactory().get(
        "/protected",
        HTTP_AUTHORIZATION=f"Bearer {token}",
    )
    response = protected(request)

    assert response.status_code == 200


def test_middleware_authenticates_when_header_exists_but_keeps_public_request_optional() -> None:
    token_provider, token, _, _, _, _ = _stack()

    def view(request: HttpRequest) -> HttpResponse:
        claims = get_authenticated_claims(request)
        return JsonResponse({"authenticated": claims is not None})

    with override_settings(PYIAMKIT_TOKEN_PROVIDER=token_provider):
        middleware = PyIAMKitAuthenticationMiddleware(view)

        anonymous = middleware(RequestFactory().get("/public"))
        authenticated = middleware(
            RequestFactory().get(
                "/public",
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )
        )

    assert _json(anonymous) == {"authenticated": False}
    assert _json(authenticated) == {"authenticated": True}


def test_permission_required_allows_verified_aal2_mfa_and_attaches_decision() -> None:
    token_provider, token, engine, permission, tenant, resolve_tenant = _stack()

    @permission_required(
        token_provider=token_provider,
        authorization_engine=engine,
        permission=permission.code,
        tenant_resolver=resolve_tenant,
    )
    def protected(request: HttpRequest) -> HttpResponse:
        decision = get_authorization_decision(request)
        assert decision is not None
        return JsonResponse({"allowed": decision.allowed})

    response = protected(
        RequestFactory().get(
            "/invoice",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
    )

    assert response.status_code == 200
    assert _json(response) == {"allowed": True}


def test_permission_required_returns_structured_step_up_403_for_aal1() -> None:
    token_provider, token, engine, permission, _, resolve_tenant = _stack(
        assurance_level=AssuranceLevel.AAL1,
        mfa=False,
    )

    @permission_required(
        token_provider=token_provider,
        authorization_engine=engine,
        permission=permission.code,
        tenant_resolver=resolve_tenant,
    )
    def protected(_request: HttpRequest) -> HttpResponse:
        return JsonResponse({"unexpected": True})

    response = protected(
        RequestFactory().get(
            "/invoice",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
    )

    assert response.status_code == 403
    assert _json(response) == {
        "detail": {
            "code": "step_up_required",
            "required_assurance_level": "aal2",
            "required_mfa": True,
        }
    }
    assert "WWW-Authenticate" not in response


def test_permission_required_keeps_ordinary_authorization_denial_generic() -> None:
    token_provider, token, engine, _, _, resolve_tenant = _stack()

    @permission_required(
        token_provider=token_provider,
        authorization_engine=engine,
        permission=PermissionCode("invoice.delete"),
        tenant_resolver=resolve_tenant,
    )
    def protected(_request: HttpRequest) -> HttpResponse:
        return JsonResponse({"unexpected": True})

    response = protected(
        RequestFactory().get(
            "/invoice",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
    )

    assert response.status_code == 403
    assert _json(response) == {"detail": "Forbidden"}


def test_decorator_can_resolve_provider_from_django_settings() -> None:
    token_provider, token, _, _, _, _ = _stack()

    @bearer_required()
    def protected(request: HttpRequest) -> HttpResponse:
        return JsonResponse({"authenticated": get_authenticated_claims(request) is not None})

    with override_settings(PYIAMKIT_TOKEN_PROVIDER=token_provider):
        response = protected(
            RequestFactory().get(
                "/protected",
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )
        )

    assert response.status_code == 200


def test_missing_provider_configuration_is_explicit() -> None:
    @bearer_required()
    def protected(_request: HttpRequest) -> HttpResponse:
        return JsonResponse({"unexpected": True})

    request = RequestFactory().get("/protected", HTTP_AUTHORIZATION="Bearer token")

    with override_settings():
        if hasattr(settings, "PYIAMKIT_TOKEN_PROVIDER"):
            del settings.PYIAMKIT_TOKEN_PROVIDER
        with pytest.raises(ImproperlyConfigured, match="PYIAMKIT_TOKEN_PROVIDER"):
            protected(request)


def test_async_views_are_rejected_in_sync_integration() -> None:
    async def async_view(_request: HttpRequest) -> HttpResponse:
        return JsonResponse({"ok": True})

    with pytest.raises(ImproperlyConfigured, match="synchronous"):
        bearer_required(object())(async_view)  # type: ignore[arg-type]
