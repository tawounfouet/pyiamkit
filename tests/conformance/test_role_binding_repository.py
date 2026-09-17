from datetime import UTC, datetime

from pyiamkit.authorization import RoleBinding, RoleId
from pyiamkit.authorization.adapters import InMemoryRoleBindingRepository
from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId, TenantScope

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_role_binding_repository_is_tenant_partitioned_and_returns_copies() -> None:
    repository = InMemoryRoleBindingRepository()
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()
    binding = RoleBinding.create(
        identity_id=identity_id,
        role_id=RoleId.new(),
        tenant_id=tenant_id,
        scope=TenantScope(tenant_id),
        created_at=NOW,
    )
    binding.pull_events()
    repository.save(binding)

    loaded = repository.get(binding.id)
    assert loaded is not None
    assert loaded is not binding
    assert loaded.id == binding.id
    assert repository.find_active_for_subject(identity_id, tenant_id, NOW) == (loaded,)
    assert repository.find_active_for_subject(identity_id, TenantId.new(), NOW) == ()
