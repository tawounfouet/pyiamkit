"""SCIM Group provisioning orchestration."""

import re
from collections.abc import Mapping

from pyiamkit.shared import Clock, DomainEvent, DomainEventSink

from .application import ProvisioningSource
from .domain import ProvisioningResourceId, ProvisioningResourceStatus, ProvisioningUser
from .errors import (
    InvalidScimRequest,
    ProvisioningConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceNotFound,
    UnsupportedScimPatch,
)
from .group_domain import ProvisioningGroup
from .group_scim import (
    ScimGroupInput,
    ScimGroupListResponse,
    ScimGroupMember,
    ScimGroupPatchOperation,
    ScimGroupResource,
    group_member_ref,
    group_resource_location,
)
from .ports import ProvisioningGroupRepository, ProvisioningUserRepository
from .scim import ScimMeta, ScimPatchVerb

_MEMBER_FILTER_RE = re.compile(
    r'^members\[value\s+eq\s+"(?P<value>[^"]+)"\]$',
    re.IGNORECASE,
)


class ScimGroupProvisioningService:
    """Manage source-scoped SCIM Groups without granting authorization."""

    def __init__(
        self,
        *,
        source: ProvisioningSource,
        group_repository: ProvisioningGroupRepository,
        user_repository: ProvisioningUserRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._source = source
        self._groups = group_repository
        self._users = user_repository
        self._clock = clock
        self._events = event_sink

    def create_group(self, group: ScimGroupInput) -> ScimGroupResource:
        self._ensure_unique(group)
        member_ids = self._validated_member_ids(group.members)
        resource = ProvisioningGroup.create(
            source_id=self._source.source_id,
            tenant_id=self._source.tenant_id,
            display_name=group.display_name,
            external_id=group.external_id,
            member_ids=member_ids,
            created_at=self._clock.now(),
        )
        self._groups.save(resource)
        self._publish("ScimGroupProvisioned", resource)
        return self._render(resource)

    def get_group(self, resource_id: ProvisioningResourceId) -> ScimGroupResource:
        return self._render(self._require_resource(resource_id))

    def find_by_external_id(self, external_id: str) -> ScimGroupResource | None:
        resource = self._groups.find_by_external_id(self._source.source_id, external_id)
        return None if resource is None else self._render(resource)

    def find_by_display_name(self, display_name: str) -> ScimGroupResource | None:
        resource = self._groups.find_by_display_name(self._source.source_id, display_name)
        return None if resource is None else self._render(resource)

    def list_groups(
        self,
        *,
        start_index: int = 1,
        count: int = 100,
    ) -> ScimGroupListResponse:
        if start_index < 1:
            raise ValueError("SCIM startIndex must be at least 1")
        if count < 0:
            raise ValueError("SCIM count must not be negative")
        resources = self._groups.list_for_source(
            self._source.source_id,
            self._source.tenant_id,
        )
        total = len(resources)
        start = start_index - 1
        page = resources[start : start + count]
        rendered = tuple(self._render(resource) for resource in page)
        return ScimGroupListResponse(
            total_results=total,
            start_index=start_index,
            items_per_page=len(rendered),
            resources=rendered,
        )

    def replace_group(
        self,
        resource_id: ProvisioningResourceId,
        group: ScimGroupInput,
        *,
        if_match: str | None = None,
    ) -> ScimGroupResource:
        resource = self._require_resource(resource_id)
        self._require_match(resource, if_match)
        self._ensure_unique(group, current_id=resource.id)
        member_ids = self._validated_member_ids(group.members)
        resource.replace(
            display_name=group.display_name,
            external_id=group.external_id,
            member_ids=member_ids,
            at=self._clock.now(),
        )
        self._groups.save(resource)
        self._publish("ScimGroupReplaced", resource)
        return self._render(resource)

    def patch_group(
        self,
        resource_id: ProvisioningResourceId,
        operations: tuple[ScimGroupPatchOperation, ...],
        *,
        if_match: str | None = None,
    ) -> ScimGroupResource:
        resource = self._require_resource(resource_id)
        self._require_match(resource, if_match)

        for operation in operations:
            self._apply_patch(resource, operation)

        self._ensure_unique_resource(resource)
        self._groups.save(resource)
        self._publish("ScimGroupPatched", resource)
        return self._render(resource)

    def delete_group(
        self,
        resource_id: ProvisioningResourceId,
        *,
        if_match: str | None = None,
    ) -> None:
        resource = self._require_resource(resource_id)
        self._require_match(resource, if_match)
        resource.delete(at=self._clock.now())
        self._groups.save(resource)
        self._publish("ScimGroupDeleted", resource)

    def _apply_patch(
        self,
        resource: ProvisioningGroup,
        operation: ScimGroupPatchOperation,
    ) -> None:
        path = operation.path
        if path is None:
            if operation.op is not ScimPatchVerb.REPLACE:
                raise UnsupportedScimPatch("Pathless SCIM Group PATCH requires replace")
            self._apply_pathless_replace(resource, operation.value)
            return

        normalized = path.casefold()
        if normalized == "displayname":
            if operation.op is ScimPatchVerb.REMOVE:
                raise UnsupportedScimPatch("SCIM Group displayName cannot be removed")
            resource.rename(
                _required_text(operation.value, "displayName"),
                at=self._clock.now(),
            )
            return

        if normalized == "externalid":
            resource.set_external_id(
                None
                if operation.op is ScimPatchVerb.REMOVE
                else _required_text(operation.value, "externalId"),
                at=self._clock.now(),
            )
            return

        if normalized == "members":
            self._apply_members_patch(resource, operation)
            return

        member_match = _MEMBER_FILTER_RE.fullmatch(path)
        if member_match is not None:
            if operation.op is not ScimPatchVerb.REMOVE:
                raise UnsupportedScimPatch("Filtered SCIM Group member path only supports remove")
            member_id = self._parse_member_id(member_match.group("value"))
            resource.remove_members((member_id,), at=self._clock.now())
            return

        raise UnsupportedScimPatch(f"Unsupported SCIM Group PATCH path: {path!r}")

    def _apply_pathless_replace(
        self,
        resource: ProvisioningGroup,
        value: object,
    ) -> None:
        if not isinstance(value, Mapping):
            raise InvalidScimRequest("Pathless SCIM Group replace value must be an object")
        display_name = value.get("displayName")
        if display_name is not None:
            resource.rename(_required_text(display_name, "displayName"), at=self._clock.now())
        external_id = value.get("externalId")
        if external_id is not None:
            resource.set_external_id(
                _required_text(external_id, "externalId"),
                at=self._clock.now(),
            )
        if "members" in value:
            members = _parse_members(value["members"])
            resource.replace_members(
                self._validated_member_ids(members),
                at=self._clock.now(),
            )

    def _apply_members_patch(
        self,
        resource: ProvisioningGroup,
        operation: ScimGroupPatchOperation,
    ) -> None:
        if operation.op is ScimPatchVerb.REMOVE and operation.value is None:
            resource.replace_members((), at=self._clock.now())
            return
        members = _parse_members(operation.value)
        member_ids = self._validated_member_ids(members)
        if operation.op is ScimPatchVerb.ADD:
            resource.add_members(member_ids, at=self._clock.now())
        elif operation.op is ScimPatchVerb.REPLACE:
            resource.replace_members(member_ids, at=self._clock.now())
        else:
            resource.remove_members(member_ids, at=self._clock.now())

    def _validated_member_ids(
        self,
        members: tuple[ScimGroupMember, ...],
    ) -> tuple[ProvisioningResourceId, ...]:
        ids: list[ProvisioningResourceId] = []
        for member in members:
            member_id = self._parse_member_id(member.value)
            user = self._users.get(member_id)
            if not self._is_managed_user(user):
                raise InvalidScimRequest(
                    f"SCIM Group member {member.value!r} must reference an active managed User"
                )
            ids.append(member_id)
        return tuple(ids)

    def _parse_member_id(self, value: str) -> ProvisioningResourceId:
        try:
            return ProvisioningResourceId.parse(value)
        except (TypeError, ValueError) as exc:
            raise InvalidScimRequest(
                f"SCIM Group member {value!r} is not a valid User resource id"
            ) from exc

    def _is_managed_user(self, user: ProvisioningUser | None) -> bool:
        return (
            user is not None
            and user.status is ProvisioningResourceStatus.ACTIVE
            and user.source_id == self._source.source_id
            and user.tenant_id == self._source.tenant_id
        )

    def _ensure_unique(
        self,
        group: ScimGroupInput,
        *,
        current_id: ProvisioningResourceId | None = None,
    ) -> None:
        by_name = self._groups.find_by_display_name(
            self._source.source_id,
            group.display_name,
        )
        if by_name is not None and by_name.id != current_id:
            raise ProvisioningConflict(
                f"SCIM Group displayName {group.display_name!r} already exists"
            )
        if group.external_id is not None:
            by_external = self._groups.find_by_external_id(
                self._source.source_id,
                group.external_id,
            )
            if by_external is not None and by_external.id != current_id:
                raise ProvisioningConflict(
                    f"SCIM Group externalId {group.external_id!r} already exists for source"
                )

    def _ensure_unique_resource(self, resource: ProvisioningGroup) -> None:
        self._ensure_unique(
            ScimGroupInput(
                display_name=resource.display_name,
                external_id=resource.external_id,
            ),
            current_id=resource.id,
        )

    def _require_resource(self, resource_id: ProvisioningResourceId) -> ProvisioningGroup:
        resource = self._groups.get(resource_id)
        if resource is None or resource.status is ProvisioningResourceStatus.DELETED:
            raise ProvisioningResourceNotFound(resource_id)
        if (
            resource.source_id != self._source.source_id
            or resource.tenant_id != self._source.tenant_id
        ):
            raise ProvisioningResourceNotFound(resource_id)
        return resource

    @staticmethod
    def _require_match(resource: ProvisioningGroup, if_match: str | None) -> None:
        if if_match is None or if_match.strip() == "*":
            return
        if if_match.strip() != resource.etag:
            raise ProvisioningPreconditionFailed(
                f"SCIM resource version mismatch: expected {resource.etag}"
            )

    def _render(self, resource: ProvisioningGroup) -> ScimGroupResource:
        members: list[ScimGroupMember] = []
        for member_id in resource.member_ids:
            user = self._users.get(member_id)
            if not self._is_managed_user(user):
                raise InvalidScimRequest(
                    f"SCIM Group contains unavailable managed User {member_id}"
                )
            assert user is not None
            members.append(
                ScimGroupMember(
                    value=str(member_id),
                    display=user.user_name,
                    ref=group_member_ref(self._source.base_url, str(member_id)),
                )
            )
        return ScimGroupResource(
            id=str(resource.id),
            group=ScimGroupInput(
                display_name=resource.display_name,
                external_id=resource.external_id,
                members=tuple(members),
            ),
            meta=ScimMeta(
                resource_type="Group",
                created=resource.created_at,
                last_modified=resource.updated_at,
                version=resource.etag,
                location=group_resource_location(self._source.base_url, str(resource.id)),
            ),
        )

    def _publish(self, event_type: str, resource: ProvisioningGroup) -> None:
        self._events.publish(
            (
                DomainEvent(
                    event_type=event_type,
                    occurred_at=self._clock.now(),
                    metadata={
                        "resource_id": str(resource.id),
                        "tenant_id": str(resource.tenant_id),
                        "source_id": resource.source_id,
                        "version": resource.version,
                        "member_count": len(resource.member_ids),
                    },
                ),
            )
        )


def _parse_members(value: object) -> tuple[ScimGroupMember, ...]:
    if not isinstance(value, list):
        raise InvalidScimRequest("SCIM Group members value must be an array")
    members: list[ScimGroupMember] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise InvalidScimRequest("SCIM Group member entries must be objects")
        raw_value = item.get("value")
        if not isinstance(raw_value, str):
            raise InvalidScimRequest("SCIM Group member value must be a string")
        raw_display = item.get("display")
        if raw_display is not None and not isinstance(raw_display, str):
            raise InvalidScimRequest("SCIM Group member display must be a string")
        members.append(ScimGroupMember(value=raw_value, display=raw_display))
    return tuple(members)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidScimRequest(f"SCIM Group {field} must be a non-empty string")
    return value.strip()
