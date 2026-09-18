"""SCIM 2.0 Group representation and PATCH contracts."""

from dataclasses import dataclass
from urllib.parse import urljoin

from .errors import InvalidScimRequest
from .scim import SCIM_LIST_RESPONSE_SCHEMA, SCIM_PATCH_SCHEMA, ScimMeta, ScimPatchVerb

SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"


@dataclass(frozen=True, slots=True)
class ScimGroupMember:
    value: str
    display: str | None = None
    ref: str | None = None

    def __post_init__(self) -> None:
        value = self.value.strip()
        if not value:
            raise InvalidScimRequest("SCIM Group member value must not be empty")
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "display", _optional_text(self.display))
        object.__setattr__(self, "ref", _optional_text(self.ref))

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"value": self.value}
        if self.display is not None:
            result["display"] = self.display
        if self.ref is not None:
            result["$ref"] = self.ref
        return result


@dataclass(frozen=True, slots=True)
class ScimGroupInput:
    display_name: str
    external_id: str | None = None
    members: tuple[ScimGroupMember, ...] = ()

    def __post_init__(self) -> None:
        display_name = self.display_name.strip()
        if not display_name:
            raise InvalidScimRequest("SCIM Group displayName is required")
        values = [member.value for member in self.members]
        if len(values) != len(set(values)):
            raise InvalidScimRequest("SCIM Group members must be unique")
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "external_id", _optional_text(self.external_id))


@dataclass(frozen=True, slots=True)
class ScimGroupResource:
    id: str
    group: ScimGroupInput
    meta: ScimMeta

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": self.id,
            "displayName": self.group.display_name,
            "members": [member.to_dict() for member in self.group.members],
            "meta": self.meta.to_dict(),
        }
        if self.group.external_id is not None:
            result["externalId"] = self.group.external_id
        return result


@dataclass(frozen=True, slots=True)
class ScimGroupListResponse:
    total_results: int
    start_index: int
    items_per_page: int
    resources: tuple[ScimGroupResource, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
            "totalResults": self.total_results,
            "startIndex": self.start_index,
            "itemsPerPage": self.items_per_page,
            "Resources": [resource.to_dict() for resource in self.resources],
        }


@dataclass(frozen=True, slots=True)
class ScimGroupPatchOperation:
    op: ScimPatchVerb
    path: str | None = None
    value: object | None = None

    def __post_init__(self) -> None:
        if self.path is not None:
            path = self.path.strip()
            object.__setattr__(self, "path", path or None)


def group_resource_location(base_url: str | None, resource_id: str) -> str | None:
    if base_url is None:
        return None
    normalized = base_url.rstrip("/") + "/"
    return urljoin(normalized, f"Groups/{resource_id}")


def group_member_ref(base_url: str | None, resource_id: str) -> str | None:
    if base_url is None:
        return None
    normalized = base_url.rstrip("/") + "/"
    return urljoin(normalized, f"Users/{resource_id}")


def require_group_patch_schema(schemas: object) -> None:
    if not isinstance(schemas, list) or SCIM_PATCH_SCHEMA not in schemas:
        raise InvalidScimRequest(f"SCIM schemas must include {SCIM_PATCH_SCHEMA!r}")


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
