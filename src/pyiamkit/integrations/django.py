"""Synchronous Django integration for PyIAMKit authentication and authorization."""

from collections.abc import Callable
from functools import wraps
from inspect import iscoroutinefunction
from typing import Any, ParamSpec, Protocol, TypeVar, cast

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.module_loading import import_string

from pyiamkit.authentication import AccessTokenClaims, InvalidAccessToken, TokenProvider
from pyiamkit.authorization import (
    AuthenticationEvidence,
    AuthorizationDecision,
    AuthorizationEngine,
    AuthorizationRequest,
    PermissionCode,
    ResourceDescriptor,
)
from pyiamkit.tenancy import TenantId, TenantScope

P = ParamSpec("P")
R = TypeVar("R", bound=HttpResponse)

_CLAIMS_ATTRIBUTE = "pyiamkit_claims"
_AUTHENTICATION_ERROR_ATTRIBUTE = "pyiamkit_authentication_error"


class DjangoTenantResolver(Protocol):
    def __call__(self, request: HttpRequest, claims: AccessTokenClaims) -> TenantId: ...


class DjangoScopeResolver(Protocol):
    def __call__(
        self,
        request: HttpRequest,
        claims: AccessTokenClaims,
        tenant_id: TenantId,
    ) -> TenantScope: ...


class DjangoResourceResolver(Protocol):
    def __call__(
        self,
        request: HttpRequest,
        claims: AccessTokenClaims,
        tenant_id: TenantId,
    ) -> ResourceDescriptor | None: ...


class DjangoCorrelationIdResolver(Protocol):
    def __call__(self, request: HttpRequest) -> str | None: ...


class DjangoAuthenticationRequired(Exception):
    """Internal adapter signal mapped to an HTTP 401 response."""


def authenticate_request(
    request: HttpRequest,
    token_provider: TokenProvider,
) -> AccessTokenClaims:
    """Verify a Bearer credential from a Django request."""

    authorization = request.headers.get("Authorization")
    if authorization is None:
        raise DjangoAuthenticationRequired("Bearer credential is missing")

    scheme, separator, credential = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not credential.strip():
        raise DjangoAuthenticationRequired("Bearer credential is malformed")

    try:
        return token_provider.verify_access_token(credential.strip())
    except InvalidAccessToken as exc:
        raise DjangoAuthenticationRequired("Bearer credential is invalid") from exc


def get_authenticated_claims(request: HttpRequest) -> AccessTokenClaims | None:
    """Read claims attached by middleware/decorators without trusting arbitrary request data."""

    value = getattr(request, _CLAIMS_ATTRIBUTE, None)
    return value if isinstance(value, AccessTokenClaims) else None


class PyIAMKitAuthenticationMiddleware:
    """Optionally authenticate Bearer credentials and attach verified claims to the request.

    The middleware does not reject public requests by itself. Protected decorators decide
    whether authentication is mandatory.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self._get_response = get_response
        self._token_provider = _configured_token_provider()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.headers.get("Authorization") is None:
            return self._get_response(request)

        try:
            claims = authenticate_request(request, self._token_provider)
        except DjangoAuthenticationRequired as exc:
            setattr(request, _AUTHENTICATION_ERROR_ATTRIBUTE, exc)
        else:
            setattr(request, _CLAIMS_ATTRIBUTE, claims)

        return self._get_response(request)


def bearer_required(
    token_provider: TokenProvider | None = None,
) -> Callable[[Callable[P, R]], Callable[P, HttpResponse]]:
    """Protect a synchronous Django view with PyIAMKit Bearer authentication."""

    def decorator(view: Callable[P, R]) -> Callable[P, HttpResponse]:
        _require_sync_view(view)

        @wraps(view)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            request = _request_from_args(args)
            claims = get_authenticated_claims(request)
            if claims is None:
                provider = token_provider or _configured_token_provider()
                try:
                    claims = authenticate_request(request, provider)
                except DjangoAuthenticationRequired:
                    return _authentication_required_response()
                setattr(request, _CLAIMS_ATTRIBUTE, claims)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def permission_required(
    *,
    authorization_engine: AuthorizationEngine,
    permission: PermissionCode,
    tenant_resolver: DjangoTenantResolver,
    token_provider: TokenProvider | None = None,
    scope_resolver: DjangoScopeResolver | None = None,
    resource_resolver: DjangoResourceResolver | None = None,
    correlation_id_resolver: DjangoCorrelationIdResolver | None = None,
) -> Callable[[Callable[P, R]], Callable[P, HttpResponse]]:
    """Protect a synchronous Django view with Authentication + Authorization."""

    def decorator(view: Callable[P, R]) -> Callable[P, HttpResponse]:
        _require_sync_view(view)

        @wraps(view)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            request = _request_from_args(args)
            claims = get_authenticated_claims(request)
            if claims is None:
                provider = token_provider or _configured_token_provider()
                try:
                    claims = authenticate_request(request, provider)
                except DjangoAuthenticationRequired:
                    return _authentication_required_response()
                setattr(request, _CLAIMS_ATTRIBUTE, claims)

            tenant_id = tenant_resolver(request, claims)
            scope = (
                TenantScope(tenant_id)
                if scope_resolver is None
                else scope_resolver(request, claims, tenant_id)
            )
            resource = (
                None
                if resource_resolver is None
                else resource_resolver(request, claims, tenant_id)
            )
            correlation_id = (
                request.headers.get("X-Request-ID")
                if correlation_id_resolver is None
                else correlation_id_resolver(request)
            )

            decision = authorization_engine.authorize(
                AuthorizationRequest(
                    subject_id=claims.subject_id,
                    tenant_id=tenant_id,
                    permission=permission,
                    scope=scope,
                    resource=resource,
                    authentication=AuthenticationEvidence(
                        assurance_level=claims.assurance_level,
                        mfa=claims.mfa,
                        authenticated_at=claims.auth_time,
                    ),
                    correlation_id=correlation_id,
                )
            )
            if not decision.allowed:
                return _authorization_denied_response(decision)

            setattr(request, "pyiamkit_authorization_decision", decision)
            return view(*args, **kwargs)

        return wrapper

    return decorator


def get_authorization_decision(request: HttpRequest) -> AuthorizationDecision | None:
    value = getattr(request, "pyiamkit_authorization_decision", None)
    return value if isinstance(value, AuthorizationDecision) else None


def _configured_token_provider() -> TokenProvider:
    if not hasattr(settings, "PYIAMKIT_TOKEN_PROVIDER"):
        raise ImproperlyConfigured(
            "PYIAMKIT_TOKEN_PROVIDER must be configured or token_provider supplied explicitly"
        )
    configured = settings.PYIAMKIT_TOKEN_PROVIDER
    value: object
    if isinstance(configured, str):
        value = import_string(configured)
    else:
        value = configured
    if not hasattr(value, "verify_access_token"):
        raise ImproperlyConfigured("PYIAMKIT_TOKEN_PROVIDER does not expose verify_access_token")
    return cast(TokenProvider, value)


def _request_from_args(args: tuple[Any, ...]) -> HttpRequest:
    if not args or not isinstance(args[0], HttpRequest):
        raise TypeError("PyIAMKit Django decorators require HttpRequest as the first argument")
    return args[0]


def _require_sync_view(view: Callable[..., object]) -> None:
    if iscoroutinefunction(view):
        raise ImproperlyConfigured(
            "PyIAMKit Django integration is synchronous; async views are not supported"
        )


def _authentication_required_response() -> JsonResponse:
    response = JsonResponse({"detail": "Not authenticated"}, status=401)
    response["WWW-Authenticate"] = "Bearer"
    return response


def _authorization_denied_response(decision: AuthorizationDecision) -> JsonResponse:
    if decision.step_up_required:
        return JsonResponse(
            {
                "detail": {
                    "code": "step_up_required",
                    "required_assurance_level": (
                        None
                        if decision.required_assurance_level is None
                        else decision.required_assurance_level.value
                    ),
                    "required_mfa": decision.required_mfa,
                }
            },
            status=403,
        )
    return JsonResponse({"detail": "Forbidden"}, status=403)
