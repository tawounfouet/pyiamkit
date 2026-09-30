"""Ports for authoritative security-state version reads and mutations."""

from typing import Protocol

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .state import SecurityStateStamp, StateVersion


class SecurityStateReader(Protocol):
    """Read the current security-state stamp for one subject and tenant."""

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp: ...


class SecurityStateWriter(Protocol):
    """Advance authoritative security-state versions after security mutations."""

    def bump_runtime_generation(self) -> StateVersion: ...

    def bump_identity(self, identity_id: IdentityId) -> StateVersion: ...

    def bump_tenant(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_membership(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion: ...

    def bump_subject_authorization(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion: ...

    def bump_tenant_authorization(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_global_authorization(self) -> StateVersion: ...

    def bump_governance(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_authentication(self, identity_id: IdentityId) -> StateVersion: ...
