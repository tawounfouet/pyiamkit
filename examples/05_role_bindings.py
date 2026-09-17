"""Scoped RoleBinding shape introduced in 0.1.0b2."""

from datetime import UTC, datetime

from pyiamkit.authorization import RoleBinding, RoleId
from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId, TenantScope

now = datetime.now(UTC)
tenant_id = TenantId.new()
binding = RoleBinding.create(
    identity_id=IdentityId.new(),
    role_id=RoleId.new(),
    tenant_id=tenant_id,
    scope=TenantScope(tenant_id),
    created_at=now,
    justification="Example scoped assignment",
)

print(binding.status.value, binding.scope.tenant_id)
