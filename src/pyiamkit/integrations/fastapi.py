"""FastAPI dependencies for PyIAMKit authentication and authorization."""

from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pyiamkit.authentication import AccessTokenClaims, InvalidAccessToken, TokenProvider
from pyiamkit.authorization import (
    AuthorizationDecision,
    AuthorizationEngine,
    AuthorizationRequest,
    PermissionCode,
    ResourceDescriptor,
)
from pyiamkit.tenancy import TenantId, TenantScope

AuthenticationDependency = Callable[..., AccessTokenClaims]


class TenantResolver(Protocol):
    def __call__(self, request: Request, claims: AccessTokenClaims) -> TenantId: ...


class ScopeResolver(Protocol):
    def __call__(
        self,
        request: Request,
        claims: AccessTokenClaims,
        tenant_id: TenantId,
    ) -> TenantScope: ...


class ResourceResolver(Protocol):
    def __call__(
        self,
        request: Request,
        claims: AccessTokenClaims,
        tenant_id: TenantId,
    ) -> ResourceDescriptor | None: ...


class CorrelationIdResolver(Protocol):
    def __call__(self, request: Request) -> str | None: ...


def bearer_authentication(
    token_provider: TokenProvider,
    *,
    scheme_name: str = "PyIAMKitBearer",
    description: str = "PyIAMKit bearer access token",
) -> AuthenticationDependency:
    """Return a FastAPI dependency that verifies a PyIAMKit bearer access token."""

    bearer = HTTPBearer(
        bearerFormat="JWT",
        scheme_name=scheme_name,
        description=description,
        auto_error=False,
    )

    def dependency(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
    ) -> AccessTokenClaims:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise _not_authenticated()
        try:
            return token_provider.verify_access_token(credentials.credentials)
        except InvalidAccessToken as exc:
            raise _not_authenticated() from exc

    return dependency


def require_permission(
    *,
    authentication: AuthenticationDependency,
    authorization_engine: AuthorizationEngine,
    permission: PermissionCode,
    tenant_resolver: TenantResolver,
    scope_resolver: ScopeResolver | None = None,
    resource_resolver: ResourceResolver | None = None,
    correlation_id_resolver: CorrelationIdResolver | None = None,
) -> Callable[..., AuthorizationDecision]:
    """Return a FastAPI dependency enforcing a PyIAMKit permission."""

    def dependency(
        request: Request,
        claims: Annotated[AccessTokenClaims, Depends(authentication)],
    ) -> AuthorizationDecision:
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
            request.headers.get("x-request-id")
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
                correlation_id=correlation_id,
            )
        )
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return decision

    return dependency


def _not_authenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
