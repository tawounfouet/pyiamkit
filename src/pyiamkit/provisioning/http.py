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
from .group_application import ScimGroupProvisioningService
from .group_http import (
    group_resource_type_resource,
    group_schema_resource,
    parse_group_filter,
    parse_scim_group_patch_payload,
    parse_scim_group_payload,
)
from .group_scim import SCIM_GROUP_SCHEMA, ScimGroupListResponse, ScimGroupResource
from .providers import GENERIC_SCIM_PROFILE, ScimProviderProfile
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

_USER_PROJECTION_ATTRIBUTES = frozenset(
    {"userName", "externalId", "displayName", "active", "name", "emails"}
)
_GROUP_PROJECTION_ATTRIBUTES = frozenset({"displayName", "externalId", "members"})

_FILTER_CLAUSE_RE = re.compile(
    r"^\s*(?P<attribute>userName|externalId)\s+(?P<operator>eq)\s+(?P<value>.+?)\s*$",
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
class ScimUserFilterExpression:
    clauses: tuple[ScimUserFilter, ...]


@dataclass(frozen=True, slots=True)
class ScimAttributeSelection:
    attributes: frozenset[str] | None
    excluded_attributes: frozenset[str]


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


def parse_attribute_selection(
    *,
    attributes: str | None = None,
    excluded_attributes: str | None = None,
    allowed_attributes: frozenset[str],
) -> ScimAttributeSelection:
    selected = _parse_attribute_names(
        attributes,
        parameter="attributes",
        allowed_attributes=allowed_attributes,
    )
    excluded = _parse_attribute_names(
        excluded_attributes,
        parameter="excludedAttributes",
        allowed_attributes=allowed_attributes,
    )
    return ScimAttributeSelection(
        attributes=None if attributes is None or not attributes.strip() else selected,
        excluded_attributes=excluded,
    )


def project_scim_resource(
    payload: Mapping[str, object],
    *,
    selection: ScimAttributeSelection,
) -> dict[str, object]:
    always_returned = {"schemas", "id", "meta"}
    if selection.attributes is None:
        projected = dict(payload)
    else:
        included = always_returned.union(selection.attributes)
        projected = {key: value for key, value in payload.items() if key in included}

    for attribute in selection.excluded_attributes:
        if attribute not in always_returned:
            projected.pop(attribute, None)
    return projected


def _project_list_response(
    payload: dict[str, object],
    *,
    selection: ScimAttributeSelection,
) -> dict[str, object]:
    resources = payload.get("Resources")
    if not isinstance(resources, list):
        return payload
    projected = dict(payload)
    projected["Resources"] = [
        project_scim_resource(resource, selection=selection)
        if isinstance(resource, Mapping)
        else resource
        for resource in resources
    ]
    return projected


def parse_user_filter(value: str | None) -> ScimUserFilter | None:
    """Parse the original strict single-clause filter contract."""

    expression = parse_user_filter_expression(value, profile=GENERIC_SCIM_PROFILE)
    if expression is None:
        return None
    return expression.clauses[0]


def parse_user_filter_expression(
    value: str | None,
    *,
    profile: ScimProviderProfile = GENERIC_SCIM_PROFILE,
) -> ScimUserFilterExpression | None:
    if value is None or not value.strip():
        return None

    raw_clauses = _split_and_clauses(value)
    if len(raw_clauses) > 1 and not profile.allow_and_filters:
        raise InvalidScimRequest(
            f"SCIM provider profile {profile.kind.value!r} does not support 'and' filters"
        )

    clauses = tuple(_parse_filter_clause(clause, profile=profile) for clause in raw_clauses)
    if not clauses:
        raise InvalidScimRequest("SCIM filter must contain at least one expression")
    return ScimUserFilterExpression(clauses)


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
        provider_profile: ScimProviderProfile = GENERIC_SCIM_PROFILE,
        group_service: ScimGroupProvisioningService | None = None,
    ) -> None:
        if max_results < 1:
            raise ValueError("max_results must be at least 1")
        self._service = service
        self._base_url = None if base_url is None else base_url.rstrip("/")
        self._max_results = max_results
        self._documentation_uri = documentation_uri
        self._provider_profile = provider_profile
        self._group_service = group_service

    @property
    def groups_enabled(self) -> bool:
        return self._group_service is not None

    def get_service_provider_config(self) -> ScimHttpResponse:
        return ScimHttpResponse.json(
            200,
            service_provider_config(
                max_results=self._max_results,
                documentation_uri=self._documentation_uri,
            ),
        )

    def get_resource_types(self) -> ScimHttpResponse:
        if self._group_service is None:
            return ScimHttpResponse.json(200, resource_types_response(self._base_url))
        resources = (
            resource_type_resource(self._base_url),
            group_resource_type_resource(self._base_url),
        )
        return ScimHttpResponse.json(
            200,
            {
                "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
                "totalResults": len(resources),
                "startIndex": 1,
                "itemsPerPage": len(resources),
                "Resources": list(resources),
            },
        )

    def get_resource_type(self, resource_type: str) -> ScimHttpResponse:
        normalized = resource_type.casefold()
        if normalized == "user":
            return ScimHttpResponse.json(200, resource_type_resource(self._base_url))
        if normalized == "group" and self._group_service is not None:
            return ScimHttpResponse.json(200, group_resource_type_resource(self._base_url))
        return self._error(404, f"SCIM ResourceType {resource_type!r} was not found")

    def get_schemas(self) -> ScimHttpResponse:
        if self._group_service is None:
            return ScimHttpResponse.json(200, schemas_response(self._base_url))
        resources = (
            schema_resource(self._base_url),
            group_schema_resource(self._base_url),
        )
        return ScimHttpResponse.json(
            200,
            {
                "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
                "totalResults": len(resources),
                "startIndex": 1,
                "itemsPerPage": len(resources),
                "Resources": list(resources),
            },
        )

    def get_schema(self, schema_uri: str) -> ScimHttpResponse:
        if schema_uri == SCIM_USER_SCHEMA:
            return ScimHttpResponse.json(200, schema_resource(self._base_url))
        if schema_uri == SCIM_GROUP_SCHEMA and self._group_service is not None:
            return ScimHttpResponse.json(200, group_schema_resource(self._base_url))
        return self._error(404, f"SCIM Schema {schema_uri!r} was not found")

    def create_user(self, payload: object) -> ScimHttpResponse:
        try:
            resource = self._service.create_user(parse_scim_user_payload(payload))
            return self._resource_response(201, resource)
        except Exception as exc:
            return self._error_response(exc)

    def get_user(
        self,
        resource_id: str,
        *,
        attributes: str | None = None,
        excluded_attributes: str | None = None,
    ) -> ScimHttpResponse:
        try:
            selection = parse_attribute_selection(
                attributes=attributes,
                excluded_attributes=excluded_attributes,
                allowed_attributes=_USER_PROJECTION_ATTRIBUTES,
            )
            resource = self._service.get_user(ProvisioningResourceId.parse(resource_id))
            return self._resource_response(200, resource, selection=selection)
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
        attributes: str | None = None,
        excluded_attributes: str | None = None,
    ) -> ScimHttpResponse:
        try:
            if start_index < 1:
                raise InvalidScimRequest("SCIM startIndex must be at least 1")
            if count < 0:
                raise InvalidScimRequest("SCIM count must not be negative")
            expression = parse_user_filter_expression(
                filter_expression,
                profile=self._provider_profile,
            )
            selection = parse_attribute_selection(
                attributes=attributes,
                excluded_attributes=excluded_attributes,
                allowed_attributes=_USER_PROJECTION_ATTRIBUTES,
            )
            effective_count = min(count, self._max_results)

            if expression is None:
                result = self._service.list_users(
                    start_index=start_index,
                    count=effective_count,
                )
            else:
                match = self._find_by_expression(expression)
                result = self._filtered_list(
                    match,
                    start_index=start_index,
                    count=effective_count,
                )
            return ScimHttpResponse.json(
                200,
                _project_list_response(result.to_dict(), selection=selection),
            )
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

    def create_group(self, payload: object) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            resource = service.create_group(parse_scim_group_payload(payload))
            return self._group_resource_response(201, resource)
        except Exception as exc:
            return self._error_response(exc)

    def get_group(
        self,
        resource_id: str,
        *,
        attributes: str | None = None,
        excluded_attributes: str | None = None,
    ) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            selection = parse_attribute_selection(
                attributes=attributes,
                excluded_attributes=excluded_attributes,
                allowed_attributes=_GROUP_PROJECTION_ATTRIBUTES,
            )
            resource = service.get_group(ProvisioningResourceId.parse(resource_id))
            return self._group_resource_response(200, resource, selection=selection)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM Group {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def list_groups(
        self,
        *,
        filter_expression: str | None = None,
        start_index: int = 1,
        count: int = 100,
        attributes: str | None = None,
        excluded_attributes: str | None = None,
    ) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            if start_index < 1:
                raise InvalidScimRequest("SCIM startIndex must be at least 1")
            if count < 0:
                raise InvalidScimRequest("SCIM count must not be negative")
            group_filter = parse_group_filter(
                filter_expression,
                profile=self._provider_profile,
            )
            selection = parse_attribute_selection(
                attributes=attributes,
                excluded_attributes=excluded_attributes,
                allowed_attributes=_GROUP_PROJECTION_ATTRIBUTES,
            )
            effective_count = min(count, self._max_results)
            if group_filter is None:
                result = service.list_groups(
                    start_index=start_index,
                    count=effective_count,
                )
            else:
                attribute, value = group_filter
                match = (
                    service.find_by_display_name(value)
                    if attribute == "displayName"
                    else service.find_by_external_id(value)
                )
                result = self._filtered_group_list(
                    match,
                    start_index=start_index,
                    count=effective_count,
                )
            return ScimHttpResponse.json(
                200,
                _project_list_response(result.to_dict(), selection=selection),
            )
        except InvalidScimRequest as exc:
            return self._error(
                400,
                str(exc),
                ScimErrorType.INVALID_FILTER
                if filter_expression is not None
                else ScimErrorType.INVALID_VALUE,
            )

    def replace_group(
        self,
        resource_id: str,
        payload: object,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            resource = service.replace_group(
                parsed_id,
                parse_scim_group_payload(payload),
                if_match=if_match,
            )
            return self._group_resource_response(200, resource)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM Group {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def patch_group(
        self,
        resource_id: str,
        payload: object,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            resource = service.patch_group(
                parsed_id,
                parse_scim_group_patch_payload(payload),
                if_match=if_match,
            )
            return self._group_resource_response(200, resource)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM Group {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    def delete_group(
        self,
        resource_id: str,
        *,
        if_match: str | None = None,
    ) -> ScimHttpResponse:
        service = self._group_service
        if service is None:
            return self._error(404, "SCIM Group resource type is not configured")
        try:
            parsed_id = ProvisioningResourceId.parse(resource_id)
            service.delete_group(parsed_id, if_match=if_match)
            return ScimHttpResponse.empty(204)
        except (ValueError, TypeError):
            return self._error(404, f"SCIM Group {resource_id!r} was not found")
        except Exception as exc:
            return self._error_response(exc)

    @staticmethod
    def _group_resource_response(
        status: int,
        resource: ScimGroupResource,
        *,
        selection: ScimAttributeSelection | None = None,
    ) -> ScimHttpResponse:
        payload = resource.to_dict()
        if selection is not None:
            payload = project_scim_resource(payload, selection=selection)
        return ScimHttpResponse.json(
            status,
            payload,
            location=resource.meta.location,
            etag=resource.meta.version,
        )

    @staticmethod
    def _filtered_group_list(
        resource: ScimGroupResource | None,
        *,
        start_index: int,
        count: int,
    ) -> ScimGroupListResponse:
        resources: tuple[ScimGroupResource, ...] = (
            () if resource is None or start_index > 1 or count == 0 else (resource,)
        )
        return ScimGroupListResponse(
            total_results=0 if resource is None else 1,
            start_index=start_index,
            items_per_page=len(resources),
            resources=resources,
        )

    def _resource_response(
        self,
        status: int,
        resource: ScimUserResource,
        *,
        selection: ScimAttributeSelection | None = None,
    ) -> ScimHttpResponse:
        payload = resource.to_dict()
        if selection is not None:
            payload = project_scim_resource(payload, selection=selection)
        return ScimHttpResponse.json(
            status,
            payload,
            location=resource.meta.location,
            etag=resource.meta.version,
        )

    def _find_by_expression(
        self,
        expression: ScimUserFilterExpression,
    ) -> ScimUserResource | None:
        first = expression.clauses[0]
        candidate = (
            self._service.find_by_user_name(first.value)
            if first.attribute == "userName"
            else self._service.find_by_external_id(first.value)
        )
        if candidate is None:
            return None
        return (
            candidate
            if all(self._matches(candidate, clause) for clause in expression.clauses)
            else None
        )

    @staticmethod
    def _matches(resource: ScimUserResource, clause: ScimUserFilter) -> bool:
        if clause.attribute == "userName":
            return resource.user.user_name.casefold() == clause.value.casefold()
        return resource.user.external_id == clause.value

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


def _parse_filter_clause(
    value: str,
    *,
    profile: ScimProviderProfile,
) -> ScimUserFilter:
    match = _FILTER_CLAUSE_RE.fullmatch(value)
    if match is None:
        raise InvalidScimRequest("Unsupported or malformed SCIM filter")

    raw_literal = match.group("value").strip()
    if raw_literal.startswith('"'):
        if not raw_literal.endswith('"'):
            raise InvalidScimRequest("Malformed SCIM filter string literal")
        try:
            literal = json.loads(raw_literal)
        except json.JSONDecodeError as exc:
            raise InvalidScimRequest("Malformed SCIM filter string literal") from exc
        if not isinstance(literal, str):
            raise InvalidScimRequest("SCIM filter value must be a string")
    else:
        if not profile.allow_unquoted_filter_values:
            raise InvalidScimRequest(
                f"SCIM provider profile {profile.kind.value!r} requires quoted string filters"
            )
        if not raw_literal or any(character.isspace() for character in raw_literal):
            raise InvalidScimRequest("Unquoted SCIM filter values must be non-empty tokens")
        literal = raw_literal

    attribute = match.group("attribute")
    canonical = "userName" if attribute.casefold() == "username" else "externalId"
    return ScimUserFilter(canonical, literal)


def _split_and_clauses(value: str) -> tuple[str, ...]:
    clauses: list[str] = []
    start = 0
    in_quote = False
    escaped = False
    index = 0

    while index < len(value):
        character = value[index]
        if in_quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_quote = False
            index += 1
            continue

        if character == '"':
            in_quote = True
            index += 1
            continue

        if character.isspace():
            token_start = index
            while token_start < len(value) and value[token_start].isspace():
                token_start += 1
            if value[token_start : token_start + 3].casefold() == "and":
                token_end = token_start + 3
                if token_end < len(value) and value[token_end].isspace():
                    clause = value[start:index].strip()
                    if not clause:
                        raise InvalidScimRequest("Malformed SCIM 'and' filter")
                    clauses.append(clause)
                    while token_end < len(value) and value[token_end].isspace():
                        token_end += 1
                    start = token_end
                    index = token_end
                    continue
        index += 1

    if in_quote:
        raise InvalidScimRequest("Malformed SCIM filter string literal")

    final = value[start:].strip()
    if not final:
        raise InvalidScimRequest("Malformed SCIM filter")
    clauses.append(final)
    return tuple(clauses)


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


def _parse_attribute_names(
    value: str | None,
    *,
    parameter: str,
    allowed_attributes: frozenset[str],
) -> frozenset[str]:
    if value is None or not value.strip():
        return frozenset()

    canonical = {attribute.casefold(): attribute for attribute in allowed_attributes}
    parsed: set[str] = set()
    for raw in value.split(","):
        normalized = raw.strip()
        if not normalized:
            raise InvalidScimRequest(f"SCIM {parameter} contains an empty attribute")
        if "." in normalized or "[" in normalized:
            raise InvalidScimRequest(
                f"SCIM {parameter} supports top-level attributes only in this release"
            )
        attribute = canonical.get(normalized.casefold())
        if attribute is None:
            raise InvalidScimRequest(
                f"Unsupported SCIM {parameter} attribute: {normalized!r}"
            )
        parsed.add(attribute)
    return frozenset(parsed)


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
