"""Framework-neutral SCIM 2.0 HTTP protocol surface."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .application import ScimProvisioningService
from .domain import ProvisioningResourceId
from .errors import (
    InvalidScimRequest,
    ProvisioningConflict,
    ProvisioningManagedStateConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceNotFound,
    UnsupportedScimPatch,
)
from .scim import (
    SCIM_LIST_RESPONSE_SCHEMA,
    SCIM_PATCH_SCHEMA,
    SCIM_USER_SCHEMA,
    ScimEmail,
    ScimListResponse,
    ScimName,
    ScimPatchOperation,
    ScimPatchVerb,
    ScimUserInput,
    ScimUserResource,
)

SCIM_MEDIA_TYPE = "application/scim+json"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCIM_RESOURCE_TYPE_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

_FILTER_RE = re.compile(
    r'^\s*(?P<attribute>userName|externalId)\s+(?P<operator>eq)\s+(?P<value>"(?:\\.|[^"])*")\s*$',
    re.IGNORECASE,
)


class ScimErrorType(StrEnum):
    INVALID_FILTER = "invalidFilter"
    INVALID_PATH = "invalidPath"
    INVALID_SYNTAX = "invalidSyntax"
    INVALID_VALUE = "invalidValue"
    MUTABILITY = "mutability"
    UNIQUENESS = "uniqueness"


@dataclass(frozen=True, slots=True)
class ScimErrorResponse:
    status: int
    detail: str
    scim_type: ScimErrorType | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schemas": [SCIM_ERROR_SCHEMA],
            "detail": self.detail,
            "status": str(self.status),
        }
        if self.scim_type is not None:
            result["scimType"] = self.scim_type.value
        return result


@dataclass(frozen=True, slots=True)
class ScimHttpResponse:
    status: int
    body: dict[str, object] | None
    headers: Mapping[str, str]

    @classmethod
    def json(
        cls,
        status: int,
        body: dict[str, object],
        *,
        location: str | None = None,
        etag: str | None = None,
    ) -> "ScimHttpResponse":
        headers: dict[str, str] = {"Content-Type": SCIM_MEDIA_TYPE}
        if location is not None:
            headers["Location"] = location
        if etag is not None:
            headers["ETag"] = etag
        return cls(status=status, body=body, headers=headers)

    @classmethod
    def empty(cls, status: int) -> "ScimHttpResponse":
        return cls(status=status, body=None, headers={})


@dataclass(frozen=True, slots=True)
class ScimUserFilter:
    attribute: str
    value: str


@dataclass(frozen=True, slots=True)
class ScimServiceProviderConfig:
    max_results: int = 200
    documentation_uri: str | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": self.max_results},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": True},
            "authenticationSchemes": [],
        }
        if self.documentation_uri is not None:
            result["documentationUri"] = self.documentation_uri
        return result


def parse_user_filter(value: str | None) -> ScimUserFilter | None:
    if value is None or not value.strip():
        return None
    match = _FILTER_RE.fullmatch(value)
    if match is None:
        raise InvalidScimRequest("Unsupported or malformed SCIM filter")
    try:
        literal = json.loads(match.group("value"))
    except json.JSONDecodeError as exc:
        raise InvalidScimRequest("Malformed SCIM filter string literal") from exc
    if not isinstance(literal, str):
        raise InvalidScimRequest("SCIM filter value must be a string")
    attribute = match.group("attribute")
    canonical = "userName" if attribute.casefold() == "username" else "externalId"
    return ScimUserFilter(canonical, literal)


def parse_scim_user_payload(payload: object) -> ScimUserInput:
    data = _require_mapping(payload)
    _require_schema(data, SCIM_USER_SCHEMA)
    if "password" in data:
        raise InvalidScimRequest("SCIM password provisioning is not supported")

    user_name = _required_string(data.get("userName"), "userName")
    display_name = _optional_string(data.get("displayName"), "displayName")
    external_id = _optional_string(data.get("externalId"), "externalId")
    active = data.get("active", True)
    if not isinstance(active, bool):
        raise InvalidScimRequest("SCIM active must be boolean")

    name_value = data.get("name")
    name = ScimName()
    if name_value is not None:
        name_mapping = _require_mapping(name_value)
        name = ScimName(
            given_name=_optional_string(name_mapping.get("givenName"), "name.givenName"),
            family_name=_optional_string(name_mapping.get("familyName"), "name.familyName"),
        )

    emails_value = data.get("emails", [])
    if not isinstance(emails_value, list):
        raise InvalidScimRequest("SCIM emails must be an array")
    emails: list[ScimEmail] = []
    for item in emails_value:
        email = _require_mapping(item)
        value = _required_string(email.get("value"), "emails.value")
        email_type = _optional_string(email.get("type"), "emails.type")
        primary = email.get("primary", False)
        if not isinstance(primary, bool):
            raise InvalidScimRequest("SCIM emails.primary must be boolean")
        emails.append(ScimEmail(value=value, primary=primary, type=email_type))

    return ScimUserInput(
        user_name=user_name,
        display_name=display_name,
        external_id=external_id,
        active=active,
        name=name,
        emails=tuple(emails),
    )


def parse_scim_patch_payload(payload: object) -> tuple[ScimPatchOperation, ...]:
    data = _require_mapping(payload)
    _require_schema(data, SCIM_PATCH_SCHEMA)
    raw_operations = data.get("Operations")
    if not isinstance(raw_operations, list) or not raw_operations:
        raise InvalidScimRequest("SCIM PATCH Operations must be a non-empty array")

    operations: list[ScimPatchOperation] = []
    for raw in raw_operations:
        operation = _require_mapping(raw)
        raw_op = operation.get("op")
        raw_path = operation.get("path")
        if not isinstance(raw_op, str):
            raise InvalidScimRequest("SCIM PATCH op must be a string")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise InvalidScimRequest("SCIM PATCH path must be a non-empty string")
        try:
            verb = ScimPatchVerb(raw_op.strip().lower())
        except ValueError as exc:
            raise InvalidScimRequest(f"Unsupported SCIM PATCH op: {raw_op!r}") from exc
        operations.append(
            ScimPatchOperation(
                op=verb,
                path=raw_path,
                value=operation.get("value"),
            )
        )
    return tuple(operations)


def service_provider_config(
    *,
    max_results: int = 200,
    documentation_uri: str | None = None,
) -> dict[str, object]:
    if max_results < 1:
        raise ValueError("max_results must be at least 1")
    return ScimServiceProviderConfig(
        max_results=max_results,
        documentation_uri=documentation_uri,
    ).to_dict()


def resource_type_resource(base_url: str | None) -> dict[str, object]:
    endpoint = "/Users"
    location = None if base_url is None else f"{base_url.rstrip('/')}/ResourceTypes/User"
    resource: dict[str, object] = {
        "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": endpoint,
        "description": "PyIAMKit SCIM User",
        "schema": SCIM_USER_SCHEMA,
        "schemaExtensions": [],
    }
    if location is not None:
        resource["meta"] = {
            "resourceType": "ResourceType",
            "location": location,
        }
    return resource


def resource_types_response(base_url: str | None) -> dict[str, object]:
    resource = resource_type_resource(base_url)
    return {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [resource],
    }


def schema_resource(base_url: str | None) -> dict[str, object]:
    location = None if base_url is None else f"{base_url.rstrip('/')}/Schemas/{SCIM_USER_SCHEMA}"
    resource: dict[str, object] = {
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "PyIAMKit supported SCIM User schema subset",
        "attributes": [
            _attribute("userName", "string", required=True, uniqueness="server"),
            _attribute("externalId", "string"),
            _attribute("displayName", "string"),
            _attribute("active", "boolean"),
            _attribute(
                "name",
                "complex",
                sub_attributes=[
                    _attribute("givenName", "string"),
                    _attribute("familyName", "string"),
                ],
            ),
            _attribute(
                "emails",
                "complex",
                multi_valued=True,
                sub_attributes=[
                    _attribute("value", "string"),
                    _attribute("type", "string"),
                    _attribute("primary", "boolean"),
                ],
            ),
        ],
    }
    if location is not None:
        resource["meta"] = {
            "resourceType": "Schema",
            "location": location,
        }
    return resource


def schemas_response(base_url: str | None) -> dict[str, object]:
    resource = schema_resource(base_url)
    return {
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [resource],
    }


class ScimHttpTransport:
    """Translate SCIM HTTP semantics to the provisioning application service."""

    def __init__(
        self,
        service: ScimProvisioningService,
        *,
        base_url: str | None = None,
        max_results: int = 200,
        documentation_uri: str | None = None,
    ) -> None:
        if max_results < 1:
            raise ValueError("max_results must be at least 1")
        self._service = service
        self._base_url = None if base_url is None else base_url.rstrip("/")
        self._max_results = max_results
        self._documentation_uri = documentation_uri

    def get_service_provider_config(self) -> ScimHttpResponse:
        return ScimHttpResponse.json(
            200,
            service_provider_config(
                max_results=self._max_results,
                documentation_uri=self._documentation_uri,
            ),
        )

    def get_resource_types(self) -> ScimHttpResponse:
        return ScimHttpResponse.json(200, resource_types_response(self._base_url))

    def get_resource_type(self, resource_type: str) -> ScimHttpResponse:
        if resource_type.casefold() != "user":
            return self._error(404, f"SCIM ResourceType {resource_type!r} was not found")
        return ScimHttpResponse.json(200, resource_type_resource(self._base_url))

    def get_schemas(self) -> ScimHttpResponse:
        return ScimHttpResponse.json(200, schemas_response(self._base_url))

    def get_schema(self, schema_uri: str) -> ScimHttpResponse:
        if schema_uri != SCIM_USER_SCHEMA:
            return self._error(404, f"SCIM Schema {schema_uri!r} was not found")
        return ScimHttpResponse.json(200, schema_resource(self._base_url))

    def create_user(self, payload: object) -> ScimHttpResponse:
        try:
            resource = self._service.create_user(parse_scim_user_payload(payload))
            return self._resource_response(201, resource)
        except Exception as exc:
            return self._error_response(exc)

    def get_user(self, resource_id: str) -> ScimHttpResponse:
        try:
            resource = self._service.get_user(ProvisioningResourceId.parse(resource_id))
            return self._resource_response(200, resource)
        except (ValueError, TypeError):
            return self._error(
                404,
                f"SCIM User {resource_id!r} was not found",
            )
        except Exception as exc:
            return self._error_response(exc)

    def list_users(
        self,
        *,
        filter_expression: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> ScimHttpResponse:
        try:
            if start_index < 1:
                raise InvalidScimRequest("SCIM startIndex must be at least 1")
            if count < 0:
                raise InvalidScimRequest("SCIM count must not be negative")
            user_filter = parse_user_filter(filter_expression)
            effective_count = min(count, self._max_results)

            if user_filter is None:
                result = self._service.list_users(
                    start_index=start_index,
                    count=effective_count,
                )
            else:
                match = (
                    self._service.find_by_user_name(user_filter.value)
                    if user_filter.attribute == "userName"
                    else self._service.find_by_external_id(user_filter.value)
                )
                result = self._filtered_list(
                    match,
                    start_index=start_index,
                    count=effective_count,
                )
            return ScimHttpResponse.json(200, result.to_dict())
        except InvalidScimRequest as exc:
            return self._error(
                400,
                str(exc),
                ScimErrorType.INVALID_FILTER
                if filter_expression is not None
                else ScimErrorType.INVALID_VALUE,
            )

    def replace_user(
        self,
        resource_id: str,
        payload: object,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            resource = self._service.replace_user(
                parsed_id,
                parse_scim_user_payload(payload),
                if_match=if_match,
            )
            return self._resource_response(200, resource)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM User {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def patch_user(
        self,
        resource_id: str,
        payload: object,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            resource = self._service.patch_user(
                parsed_id,
                parse_scim_patch_payload(payload),
                if_match=if_match,
            )
            return self._resource_response(200, resource)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM User {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def delete_user(
        self,
        resource_id: str,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            self._service.delete_user(parsed_id, if_match=if_match)
            return ScimHttpResponse.empty(204)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM User {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def _resource_response(self, status: int, resource: ScimUserResource) -> ScimHttpResponse:
        return ScimHttpResponse.json(
            status,
            resource.to_dict(),
            location=resource.meta.location,
            etag=resource.meta.version,
        )

    @staticmethod
    def _filtered_list(
        resource: ScimUserResource | None,
        *,
        start_index: int,
        count: int,
    ) -> ScimListResponse:
        resources: tuple[ScimUserResource, ...] = (
            () if resource is None or start_index > 1 or count == 0 else (resource,)
        )
        return ScimListResponse(
            total_results=0 if resource is None else 1,
            start_index=start_index,
            items_per_page=len(resources),
            resources=resources,
        )

    def _error_response(self, exc: Exception) -> ScimHttpResponse:
        if isinstance(exc, ProvisioningConflict):
            return self._error(409, str(exc), ScimErrorType.UNIQUENESS)
        if isinstance(exc, ProvisioningResourceNotFound):
            return self._error(404, str(exc))
        if isinstance(exc, ProvisioningPreconditionFailed):
            return self._error(412, str(exc))
        if isinstance(exc, UnsupportedScimPatch):
            return self._error(400, str(exc), ScimErrorType.INVALID_PATH)
        if isinstance(exc, InvalidScimRequest):
            return self._error(400, str(exc), ScimErrorType.INVALID_VALUE)
        if isinstance(exc, ProvisioningManagedStateConflict):
            return self._error(409, "Provisioned resource state conflict")
        return self._error(500, "Internal SCIM server error")

    @staticmethod
    def _error(
        status: int,
        detail: str,
        scim_type: ScimErrorType | None = None,
    ) -> ScimHttpResponse:
        return ScimHttpResponse.json(
            status,
            ScimErrorResponse(
                status=status,
                detail=detail,
                scim_type=scim_type,
            ).to_dict(),
        )


def _attribute(
    name: str,
    attribute_type: str,
    *,
    required: bool = False,
    multi_valued: bool = False,
    uniqueness: str = "none",
    sub_attributes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "name": name,
        "type": attribute_type,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": uniqueness,
    }
    if sub_attributes is not None:
        result["subAttributes"] = sub_attributes
    return result


def _require_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidScimRequest("SCIM request body must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _require_schema(data: Mapping[str, object], expected: str) -> None:
    raw_schemas = data.get("schemas")
    if not isinstance(raw_schemas, list) or expected not in raw_schemas:
        raise InvalidScimRequest(f"SCIM schemas must include {expected!r}")


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidScimRequest(f"SCIM {field} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidScimRequest(f"SCIM {field} must be a string")
    normalized = value.strip()
    return normalized or None
