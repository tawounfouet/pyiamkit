"""Run a coarse production performance sanity check.

This is deliberately not a benchmark. The threshold is wide enough to avoid
micro-performance noise while detecting catastrophic authorization regressions.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from time import perf_counter

from pyiamkit.authorization import (
    AuthorizationEngine,
    AuthorizationRequest,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.authorization.adapters import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)
from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository
from pyiamkit.shared import Clock
from pyiamkit.tenancy import Membership, Tenant, TenantScope
from pyiamkit.tenancy.adapters import InMemoryMembershipRepository, InMemoryTenantRepository

NOW = datetime(2026, 10, 3, 10, 15, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _authorization_target() -> tuple[AuthorizationEngine, AuthorizationRequest]:
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()
    permissions = InMemoryPermissionCatalogRepository()
    roles = InMemoryRoleRepository()
    bindings = InMemoryRoleBindingRepository()

    identity = Identity.create_user(display_name="RC Performance", created_at=NOW)
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identities.save(identity)

    tenant = Tenant.create(name="RC Tenant", slug="rc-tenant", created_at=NOW)
    tenant.pull_events()
    tenant.activate(at=NOW)
    tenant.pull_events()
    tenants.save(tenant)

    membership = Membership.create(
        identity_id=identity.id,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    membership.pull_events()
    membership.activate(at=NOW)
    membership.pull_events()
    memberships.save(membership)

    permission = Permission(PermissionCode("qualification.read"), "RC qualification read")
    permissions.save(permission)

    role = Role.create(
        name="RC Reader",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    role.pull_events()
    role.add_permission(permission.code, at=NOW)
    role.pull_events()
    roles.save(role)

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=role.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
    )
    binding.pull_events()
    bindings.save(binding)

    engine = AuthorizationEngine(
        identity_repository=identities,
        tenant_repository=tenants,
        membership_repository=memberships,
        permission_repository=permissions,
        role_repository=roles,
        binding_repository=bindings,
        clock=FrozenClock(),
    )
    request = AuthorizationRequest(
        subject_id=identity.id,
        tenant_id=tenant.id,
        permission=permission.code,
        scope=TenantScope(tenant.id),
    )
    return engine, request


def run_sanity(*, iterations: int, max_seconds: float) -> float:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if max_seconds <= 0:
        raise ValueError("max_seconds must be positive")

    engine, request = _authorization_target()

    start = perf_counter()
    for _ in range(iterations):
        decision = engine.authorize(request)
        if not decision.allowed:
            raise AssertionError(
                f"authorization sanity scenario unexpectedly denied: {decision.reason_code.value}"
            )
    elapsed = perf_counter() - start

    if elapsed > max_seconds:
        raise AssertionError(
            f"{iterations} authorization decisions took {elapsed:.3f}s "
            f"(budget {max_seconds:.3f}s)"
        )

    return elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--max-seconds", type=float, default=10.0)
    args = parser.parse_args()

    elapsed = run_sanity(
        iterations=args.iterations,
        max_seconds=args.max_seconds,
    )
    rate = args.iterations / elapsed if elapsed > 0 else float("inf")
    print(
        f"Authorization performance sanity passed: {args.iterations} decisions "
        f"in {elapsed:.3f}s ({rate:.0f} decisions/s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
