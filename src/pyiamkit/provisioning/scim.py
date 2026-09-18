"""SCIM 2.0 User representation and supported PATCH operations."""

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from urllib.parse import urljoin

from .errors import InvalidScimRequest, UnsupportedScimPatch

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


@dataclass(frozen=True, slots=True)
class ScimName:
    given_name: str | None = None
    family_name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "given_name", _optional_text(self.given_name))
        object.__setattr__(self, "family_name", _optional_text(self.family_name))


@dataclass(frozen=True, slots=True)
class ScimEmail:
    value: str
    primary: bool = False
    type: str | None = "work"

    def __post_init__(self) -> None:
        value = self.value.strip()
        if not value:
            raise InvalidScimRequest("SCIM email value must not be empty")
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "type", _optional_text(self.type))


@dataclass(frozen=True, slots=True)
class ScimUserInput:
    user_name: str
    display_name: str | None = None
    external_id: str | None = None
    active: bool = True
    name: ScimName = ScimName()
    emails: tuple[ScimEmail, ...] = ()

    def __post_init__(self) -> None:
        user_name = self.user_name.strip()
        if not user_name:
            raise InvalidScimRequest("SCIM userName is required")
        if sum(1 for email in self.emails if email.primary) > 1:
            raise InvalidScimRequest("SCIM User may have at most one primary email")
        object.__setattr__(self, "user_name", user_name)
        object.__setattr__(self, "display_name", _optional_text(self.display_name))
        object.__setattr__(self, "external_id", _optional_text(self.external_id))

    @property
    def primary_email(self) -> str | None:
        for email in self.emails:
            if email.primary:
                return email.value
        return None if not self.emails else self.emails[0].value

    @property
    def effective_display_name(self) -> str:
        return self.display_name or self.user_name


@dataclass(frozen=True, slots=True)
class ScimMeta:
    resource_type: str
    created: datetime
    last_modified: datetime
    version: str
    location: str | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "resourceType": self.resource_type,
            "created": _datetime(self.created),
            "lastModified": _datetime(self.last_modified),
            "version": self.version,
        }
        if self.location is not None:
            result["location"] = self.location
        return result


@dataclass(frozen=True, slots=True)
class ScimUserResource:
    id: str
    user: ScimUserInput
    meta: ScimMeta

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schemas": [SCIM_USER_SCHEMA],
            "id": self.id,
            "userName": self.user.user_name,
            "active": self.user.active,
            "meta": self.meta.to_dict(),
        }
        if self.user.external_id is not None:
            result["externalId"] = self.user.external_id
        if self.user.display_name is not None:
            result["displayName"] = self.user.display_name
        name: dict[str, str] = {}
        if self.user.name.given_name is not None:
            name["givenName"] = self.user.name.given_name
        if self.user.name.family_name is not None:
            name["familyName"] = self.user.name.family_name
        if name:
            result["name"] = name
        if self.user.emails:
            result["emails"] = [
                {
                    "value": email.value,
                    **({"type": email.type} if email.type is not None else {}),
                    **({"primary": True} if email.primary else {}),
                }
                for email in self.user.emails
            ]
        return result


@dataclass(frozen=True, slots=True)
class ScimListResponse:
    total_results: int
    start_index: int
    items_per_page: int
    resources: tuple[ScimUserResource, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
            "totalResults": self.total_results,
            "startIndex": self.start_index,
            "itemsPerPage": self.items_per_page,
            "Resources": [resource.to_dict() for resource in self.resources],
        }


class ScimPatchVerb(StrEnum):
    ADD = "add"
    REPLACE = "replace"
    REMOVE = "remove"


@dataclass(frozen=True, slots=True)
class ScimPatchOperation:
    op: ScimPatchVerb
    path: str
    value: object | None = None

    def __post_init__(self) -> None:
        path = self.path.strip()
        if not path:
            raise InvalidScimRequest("SCIM PATCH path is required")
        object.__setattr__(self, "path", path)


def apply_user_patch(
    current: ScimUserInput,
    operations: tuple[ScimPatchOperation, ...],
) -> ScimUserInput:
    """Apply the supported core User PATCH subset without array-index semantics."""

    result = current
    for operation in operations:
        path = operation.path.casefold()
        if path == "active":
            if operation.op is ScimPatchVerb.REMOVE:
                raise UnsupportedScimPatch("SCIM active cannot be removed")
            if not isinstance(operation.value, bool):
                raise InvalidScimRequest("SCIM active PATCH value must be boolean")
            result = replace(result, active=operation.value)
        elif path == "username":
            if operation.op is ScimPatchVerb.REMOVE:
                raise UnsupportedScimPatch("SCIM userName cannot be removed")
            result = replace(result, user_name=_required_text(operation.value, "userName"))
        elif path == "displayname":
            result = replace(
                result,
                display_name=(
                    None
                    if operation.op is ScimPatchVerb.REMOVE
                    else _required_text(operation.value, "displayName")
                ),
            )
        elif path == "externalid":
            result = replace(
                result,
                external_id=(
                    None
                    if operation.op is ScimPatchVerb.REMOVE
                    else _required_text(operation.value, "externalId")
                ),
            )
        elif path == "name.givenname":
            result = replace(
                result,
                name=replace(
                    result.name,
                    given_name=(
                        None
                        if operation.op is ScimPatchVerb.REMOVE
                        else _required_text(operation.value, "name.givenName")
                    ),
                ),
            )
        elif path == "name.familyname":
            result = replace(
                result,
                name=replace(
                    result.name,
                    family_name=(
                        None
                        if operation.op is ScimPatchVerb.REMOVE
                        else _required_text(operation.value, "name.familyName")
                    ),
                ),
            )
        elif path == "emails":
            if operation.op is ScimPatchVerb.REMOVE:
                result = replace(result, emails=())
            else:
                result = replace(result, emails=_parse_emails(operation.value))
        else:
            raise UnsupportedScimPatch(f"Unsupported SCIM PATCH path: {operation.path!r}")
    return result


def resource_location(base_url: str | None, resource_id: str) -> str | None:
    if base_url is None:
        return None
    normalized = base_url.rstrip("/") + "/"
    return urljoin(normalized, f"Users/{resource_id}")


def _parse_emails(value: object) -> tuple[ScimEmail, ...]:
    if not isinstance(value, list):
        raise InvalidScimRequest("SCIM emails PATCH value must be a list")
    emails: list[ScimEmail] = []
    for item in value:
        if not isinstance(item, dict):
            raise InvalidScimRequest("SCIM email entries must be objects")
        raw_value = item.get("value")
        if not isinstance(raw_value, str):
            raise InvalidScimRequest("SCIM email value must be a string")
        raw_type = item.get("type")
        if raw_type is not None and not isinstance(raw_type, str):
            raise InvalidScimRequest("SCIM email type must be a string")
        raw_primary = item.get("primary", False)
        if not isinstance(raw_primary, bool):
            raise InvalidScimRequest("SCIM email primary must be boolean")
        emails.append(ScimEmail(raw_value, primary=raw_primary, type=raw_type))
    return tuple(emails)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidScimRequest(f"SCIM {field} value must be a non-empty string")
    return value.strip()


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
