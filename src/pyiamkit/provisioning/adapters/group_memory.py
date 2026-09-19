"""In-memory reference adapter for SCIM provisioning groups."""

from pyiamkit.tenancy import TenantId

from ..domain import ProvisioningResourceId, ProvisioningResourceStatus
from ..group_domain import ProvisioningGroup


class InMemoryProvisioningGroupRepository:
    def __init__(self) -> None:
        self._items: dict[ProvisioningResourceId, ProvisioningGroup] = {}

    def get(self, resource_id: ProvisioningResourceId) -> ProvisioningGroup | None:
        resource = self._items.get(resource_id)
        return None if resource is None else self._copy(resource)

    def save(self, resource: ProvisioningGroup) -> None:
        self._items[resource.id] = self._copy(resource)

    def find_by_external_id(
        self,
        source_id: str,
        external_id: str,
    ) -> ProvisioningGroup | None:
        source = source_id.strip()
        external = external_id.strip()
        for resource in self._items.values():
            if (
                resource.status is ProvisioningResourceStatus.ACTIVE
                and resource.source_id == source
                and resource.external_id == external
            ):
                return self._copy(resource)
        return None

    def find_by_display_name(
        self,
        source_id: str,
        display_name: str,
    ) -> ProvisioningGroup | None:
        source = source_id.strip()
        name = display_name.strip().casefold()
        for resource in self._items.values():
            if (
                resource.status is ProvisioningResourceStatus.ACTIVE
                and resource.source_id == source
                and resource.display_name.casefold() == name
            ):
                return self._copy(resource)
        return None

    def list_for_source(
        self,
        source_id: str,
        tenant_id: TenantId,
    ) -> tuple[ProvisioningGroup, ...]:
        source = source_id.strip()
        resources = (
            resource
            for resource in self._items.values()
            if resource.status is ProvisioningResourceStatus.ACTIVE
            and resource.source_id == source
            and resource.tenant_id == tenant_id
        )
        return tuple(
            self._copy(resource)
            for resource in sorted(
                resources,
                key=lambda item: (item.display_name.casefold(), str(item.id)),
            )
        )

    @staticmethod
    def _copy(resource: ProvisioningGroup) -> ProvisioningGroup:
        return ProvisioningGroup._rehydrate(
            resource_id=resource.id,
            version=resource.version,
            source_id=resource.source_id,
            tenant_id=resource.tenant_id,
            display_name=resource.display_name,
            member_ids=resource.member_ids,
            status=resource.status,
            created_at=resource.created_at,
            updated_at=resource.updated_at,
            external_id=resource.external_id,
            deleted_at=resource.deleted_at,
        )
