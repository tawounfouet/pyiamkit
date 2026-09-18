"""Provisioning persistence ports."""

from typing import Protocol

from pyiamkit.tenancy import TenantId

from .domain import ProvisioningResourceId, ProvisioningUser


class ProvisioningUserRepository(Protocol):
    def get(self, resource_id: ProvisioningResourceId) -> ProvisioningUser | None: ...
    def save(self, resource: ProvisioningUser) -> None: ...
    def find_by_external_id(
        self,
        source_id: str,
        external_id: str,
    ) -> ProvisioningUser | None: ...
    def find_by_user_name(
        self,
        source_id: str,
        user_name: str,
    ) -> ProvisioningUser | None: ...
    def list_for_source(
        self,
        source_id: str,
        tenant_id: TenantId,
    ) -> tuple[ProvisioningUser, ...]: ...
