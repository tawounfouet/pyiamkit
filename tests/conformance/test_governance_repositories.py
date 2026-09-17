from decimal import Decimal

from pyiamkit.authorization import (
    DistinctActorSoDRule,
    GovernanceRuleId,
    MutuallyExclusiveRolesRule,
    NumericMaximumConstraint,
    PermissionCode,
    RoleId,
)
from pyiamkit.authorization.adapters import InMemoryConstraintRepository, InMemorySoDRuleRepository
from pyiamkit.tenancy import TenantId


def test_constraint_repository_returns_global_and_tenant_rules() -> None:
    repository = InMemoryConstraintRepository()
    permission = PermissionCode("payment.approve")
    tenant = TenantId.new()
    other = TenantId.new()
    global_rule = NumericMaximumConstraint(
        GovernanceRuleId.new(), permission, "amount", Decimal("1000"), None
    )
    tenant_rule = NumericMaximumConstraint(
        GovernanceRuleId.new(), permission, "amount", Decimal("500"), tenant
    )
    repository.save(global_rule)
    repository.save(tenant_rule)

    assert set(repository.list_for(permission, tenant)) == {global_rule, tenant_rule}
    assert repository.list_for(permission, other) == (global_rule,)


def test_sod_repository_partitions_static_and_dynamic_rules() -> None:
    repository = InMemorySoDRuleRepository()
    tenant = TenantId.new()
    static_rule = MutuallyExclusiveRolesRule(
        GovernanceRuleId.new(), "Maker Checker", RoleId.new(), RoleId.new(), tenant
    )
    dynamic_rule = DistinctActorSoDRule(
        GovernanceRuleId.new(),
        "No self approval",
        PermissionCode("payment.approve"),
        "prepared_by",
        tenant,
    )
    repository.save_static(static_rule)
    repository.save_dynamic(dynamic_rule)

    assert repository.list_static(tenant) == (static_rule,)
    assert repository.list_dynamic(PermissionCode("payment.approve"), tenant) == (dynamic_rule,)
