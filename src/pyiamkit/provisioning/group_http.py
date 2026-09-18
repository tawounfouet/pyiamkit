"""Framework-neutral HTTP parsing helpers for SCIM Groups."""

import json
import re
from collections.abc import Mapping

from .errors import InvalidScimRequest
from .group_scim import (
    SCIM_GROUP_SCHEMA,
    ScimGroupInput,
    ScimGroupMember,
    ScimGroupPatchOperation,
    require_group_patch_schema,
)
from .providers import GENERIC_SCIM_PROFILE, ScimProviderProfile
from .scim import ScimPatchVerb

_GROUP_FILTER_RE = re.compile(
    r"^\s*(?P<attribute>displayName|externalId)\s+eq\s+(?P<value>.+?)\s*$",
    re.IGNORECASE,
)


def parse_scim_group_payload(payload: object) -> ScimGroupInput:
    data = _require_mapping(payload)
    _require_schema(data, SCIM_GROUP_SCHEMA)
    display_name = _required_string(data.get("displayName"), "displayName")
    external_id = _optional_string(data.get("externalId"), "externalId")
    members = _parse_members(data.get("members", []))
    return ScimGroupInput(
        display_name=display_name,
        external_id=external_id,
        members=members,
    )


def parse_scim_group_patch_payload(payload: object) -> tuple[ScimGroupPatchOperation, ...]:
    data = _require_mapping(payload)
    require_group_patch_schema(data.get("schemas"))
    raw_operations = data.get("Operations", data.get("operations"))
    if not isinstance(raw_operations, list) or not raw_operations:
        raise InvalidScimRequest("SCIM Group PATCH Operations must be a non-empty array")

    operations: list[ScimGroupPatchOperation] = []
    for raw in raw_operations:
        operation = _require_mapping(raw)
        raw_op = operation.get("op")
        raw_path = operation.get("path")
        if not isinstance(raw_op, str):
            raise InvalidScimRequest("SCIM Group PATCH op must be a string")
        if raw_path is not None and not isinstance(raw_path, str):
            raise InvalidScimRequest("SCIM Group PATCH path must be a string")
        try:
            verb = ScimPatchVerb(raw_op.strip().lower())
        except ValueError as exc:
            raise InvalidScimRequest(f"Unsupported SCIM Group PATCH op: {raw_op!r}") from exc
        operations.append(
            ScimGroupPatchOperation(
                op=verb,
                path=raw_path,
                value=operation.get("value"),
            )
        )
    return tuple(operations)


def parse_group_filter(
    value: str | None,
    *,
    profile: ScimProviderProfile = GENERIC_SCIM_PROFILE,
) -> tuple[str, str] | None:
    if value is None or not value.strip():
        return None
    match = _GROUP_FILTER_RE.fullmatch(value)
    if match is None:
        raise InvalidScimRequest("Unsupported or malformed SCIM Group filter")
    raw_literal = match.group("value").strip()
    if raw_literal.startswith('"'):
        if not raw_literal.endswith('"'):
            raise InvalidScimRequest("Malformed SCIM Group filter string literal")
        try:
            literal = json.loads(raw_literal)
        except json.JSONDecodeError as exc:
            raise InvalidScimRequest("Malformed SCIM Group filter string literal") from exc
        if not isinstance(literal, str):
            raise InvalidScimRequest("SCIM Group filter value must be a string")
    else:
        if not profile.allow_unquoted_filter_values:
            raise InvalidScimRequest(
                f"SCIM provider profile {profile.kind.value!r} requires quoted string filters"
            )
        if not raw_literal or any(character.isspace() for character in raw_literal):
            raise InvalidScimRequest("Unquoted SCIM Group filter values must be non-empty tokens")
        literal = raw_literal
    attribute = match.group("attribute")
    canonical = "displayName" if attribute.casefold() == "displayname" else "externalId"
    return canonical, literal


def group_resource_type_resource(base_url: str | None) -> dict[str, object]:
    location = None if base_url is None else f"{base_url.rstrip('/')}/ResourceTypes/Group"
    resource: dict[str, object] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "PyIAMKit SCIM Group",
        "schema": SCIM_GROUP_SCHEMA,
        "schemaExtensions": [],
    }
    if location is not None:
        resource["meta"] = {
            "resourceType": "ResourceType",
            "location": location,
        }
    return resource


def group_schema_resource(base_url: str | None) -> dict[str, object]:
    location = None if base_url is None else f"{base_url.rstrip('/')}/Schemas/{SCIM_GROUP_SCHEMA}"
    resource: dict[str, object] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": SCIM_GROUP_SCHEMA,
        "name": "Group",
        "description": "PyIAMKit supported SCIM Group schema subset",
        "attributes": [
            _attribute("displayName", "string", required=True),
            _attribute("externalId", "string"),
            _attribute(
                "members",
                "complex",
                multi_valued=True,
                sub_attributes=[
                    _attribute("value", "string"),
                    _attribute("$ref", "reference"),
                    _attribute("display", "string"),
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


def _parse_members(value: object) -> tuple[ScimGroupMember, ...]:
    if not isinstance(value, list):
        raise InvalidScimRequest("SCIM Group members must be an array")
    members: list[ScimGroupMember] = []
    for item in value:
        member = _require_mapping(item)
        raw_value = member.get("value")
        if not isinstance(raw_value, str):
            raise InvalidScimRequest("SCIM Group member value must be a string")
        raw_display = member.get("display")
        if raw_display is not None and not isinstance(raw_display, str):
            raise InvalidScimRequest("SCIM Group member display must be a string")
        raw_ref = member.get("$ref")
        if raw_ref is not None and not isinstance(raw_ref, str):
            raise InvalidScimRequest("SCIM Group member $ref must be a string")
        members.append(
            ScimGroupMember(
                value=raw_value,
                display=raw_display,
                ref=raw_ref,
            )
        )
    return tuple(members)


def _attribute(
    name: str,
    attribute_type: str,
    *,
    required: bool = False,
    multi_valued: bool = False,
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
        "uniqueness": "none",
    }
    if sub_attributes is not None:
        result["subAttributes"] = sub_attributes
    return result


def _require_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidScimRequest("SCIM Group request body must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _require_schema(data: Mapping[str, object], expected: str) -> None:
    raw_schemas = data.get("schemas")
    if not isinstance(raw_schemas, list) or expected not in raw_schemas:
        raise InvalidScimRequest(f"SCIM schemas must include {expected!r}")


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidScimRequest(f"SCIM Group {field} must be a non-empty string")
    return value.strip()


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidScimRequest(f"SCIM Group {field} must be a string")
    normalized = value.strip()
    return normalized or None
