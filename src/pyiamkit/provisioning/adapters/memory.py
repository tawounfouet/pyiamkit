"""In-memory reference adapter for provisioning resources."""

from pyiamkit.tenancy import TenantId

from ..domain import (
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
)


class InMemoryProvisioningUserRepository:
    def __init__(self) -> None:
        self._items: dict[ProvisioningResourceId, ProvisioningUser] = {}

    def get(self, resource_id: ProvisioningResourceId) -> ProvisioningUser | None:
        resource = self._items.get(resource_id)
        return None if resource is None else self._copy(resource)

    def save(self, resource: ProvisioningUser) -> None:
        self._items[resource.id] = self._copy(resource)

    def find_by_external_id(
        self,
        source_id: str,
        external_id: str,
    ) -> ProvisioningUser | None:
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

    def find_by_user_name(
        self,
        source_id: str,
        user_name: str,
    ) -> ProvisioningUser | None:
        source = source_id.strip()
        username = user_name.strip()
        for resource in self._items.values():
            if (
                resource.status is ProvisioningResourceStatus.ACTIVE
                and resource.source_id == source
                and resource.user_name == username
            ):
                return self._copy(resource)
        return None

    def list_for_source(
        self,
        source_id: str,
        tenant_id: TenantId,
    ) -> tuple[ProvisioningUser, ...]:
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
            for resource in sorted(resources, key=lambda item: (item.user_name, str(item.id)))
        )

    @staticmethod
    def _copy(resource: ProvisioningUser) -> ProvisioningUser:
        return ProvisioningUser._rehydrate(
            resource_id=resource.id,
            version=resource.version,
            source_id=resource.source_id,
            identity_id=resource.identity_id,
            tenant_id=resource.tenant_id,
            membership_id=resource.membership_id,
            user_name=resource.user_name,
            active=resource.active,
            status=resource.status,
            created_at=resource.created_at,
            updated_at=resource.updated_at,
            external_id=resource.external_id,
            deleted_at=resource.deleted_at,
        )
