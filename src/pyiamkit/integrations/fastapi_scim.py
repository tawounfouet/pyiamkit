"""FastAPI adapter exposing the framework-neutral SCIM HTTP transport."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Query
from fastapi.responses import JSONResponse, Response

from pyiamkit.provisioning.http import ScimHttpResponse, ScimHttpTransport

ScimAccessDependency = Callable[..., object]


def create_scim_router(
    *,
    transport: ScimHttpTransport,
    access_dependency: ScimAccessDependency,
    prefix: str = "",
) -> APIRouter:
    """Create a protected FastAPI router for the supported SCIM 2.0 endpoints."""

    router = APIRouter(prefix=prefix)

    @router.get("/ServiceProviderConfig")
    def service_provider_config(
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_service_provider_config())

    @router.get("/ResourceTypes")
    def resource_types(
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_resource_types())

    @router.get("/ResourceTypes/{resource_type}")
    def resource_type(
        resource_type: str,
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_resource_type(resource_type))

    @router.get("/Schemas")
    def schemas(
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_schemas())

    @router.get("/Schemas/{schema_uri:path}")
    def schema(
        schema_uri: str,
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_schema(schema_uri))

    @router.post("/Users")
    def create_user(
        _: Annotated[object, Depends(access_dependency)],
        payload: Annotated[dict[str, object], Body()],
    ) -> Response:
        return _response(transport.create_user(payload))

    @router.get("/Users")
    def list_users(
        _: Annotated[object, Depends(access_dependency)],
        filter_expression: Annotated[str | None, Query(alias="filter")] = None,
        start_index: Annotated[int, Query(alias="startIndex")] = 1,
        count: Annotated[int, Query()] = 100,
    ) -> Response:
        return _response(
            transport.list_users(
                filter_expression=filter_expression,
                start_index=start_index,
                count=count,
            )
        )

    @router.get("/Users/{resource_id}")
    def get_user(
        resource_id: str,
        _: Annotated[object, Depends(access_dependency)],
    ) -> Response:
        return _response(transport.get_user(resource_id))

    @router.put("/Users/{resource_id}")
    def replace_user(
        resource_id: str,
        _: Annotated[object, Depends(access_dependency)],
        payload: Annotated[dict[str, object], Body()],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> Response:
        return _response(
            transport.replace_user(
                resource_id,
                payload,
                if_match=if_match,
            )
        )

    @router.patch("/Users/{resource_id}")
    def patch_user(
        resource_id: str,
        _: Annotated[object, Depends(access_dependency)],
        payload: Annotated[dict[str, object], Body()],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> Response:
        return _response(
            transport.patch_user(
                resource_id,
                payload,
                if_match=if_match,
            )
        )

    @router.delete("/Users/{resource_id}")
    def delete_user(
        resource_id: str,
        _: Annotated[object, Depends(access_dependency)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> Response:
        return _response(transport.delete_user(resource_id, if_match=if_match))

    return router


def _response(response: ScimHttpResponse) -> Response:
    headers = dict(response.headers)
    if response.body is None:
        return Response(status_code=response.status, headers=headers)
    return JSONResponse(
        status_code=response.status,
        content=response.body,
        headers=headers,
    )
