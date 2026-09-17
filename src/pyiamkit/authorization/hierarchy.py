"""Hierarchical RBAC services."""

from pyiamkit.shared import Clock, DomainEventSink

from .domain.errors import (
    RoleHierarchyCycle,
    RoleHierarchyDepthExceeded,
    RoleHierarchyTenantMismatch,
    RoleHierarchyUnavailable,
    RoleNotFound,
)
from .domain.role import Role
from .domain.value_objects import PermissionCode, RoleId, RoleStatus
from .ports import RoleRepository


class RoleHierarchyResolver:
    """Resolve Role inheritance without widening RoleBinding scope."""

    def __init__(self, role_repository: RoleRepository, *, max_depth: int = 32) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        self._roles = role_repository
        self._max_depth = max_depth

    def ancestor_ids(self, role_id: RoleId) -> frozenset[RoleId]:
        root = self._require_available(role_id)
        ancestors: set[RoleId] = set()
        self._collect_ancestors(root, ancestors, set(), depth=0)
        return frozenset(ancestors)

    def effective_permissions(self, role_id: RoleId) -> frozenset[PermissionCode]:
        permissions: set[PermissionCode] = set()
        for role in self.resolve_roles(role_id):
            permissions.update(role.permissions)
        return frozenset(permissions)

    def resolve_roles(self, role_id: RoleId) -> tuple[Role, ...]:
        root = self._require_available(role_id)
        resolved: list[Role] = []
        visited: set[RoleId] = set()
        self._walk(root, resolved, visited, set(), depth=0)
        return tuple(resolved)

    def permission_path(
        self, role_id: RoleId, permission: PermissionCode
    ) -> tuple[Role, ...] | None:
        root = self._require_available(role_id)
        return self._find_permission(root, permission, set(), depth=0)

    def _collect_ancestors(
        self,
        role: Role,
        ancestors: set[RoleId],
        stack: set[RoleId],
        *,
        depth: int,
    ) -> None:
        self._require_depth(depth)
        if role.id in stack:
            raise RoleHierarchyCycle(role.id, role.id)
        next_stack = {*stack, role.id}
        for parent_id in sorted(role.parent_role_ids, key=str):
            parent = self._require_available(parent_id)
            self._validate_edge(role, parent)
            if parent.id in next_stack:
                raise RoleHierarchyCycle(role.id, parent.id)
            if parent.id not in ancestors:
                ancestors.add(parent.id)
                self._collect_ancestors(parent, ancestors, next_stack, depth=depth + 1)

    def _walk(
        self,
        role: Role,
        resolved: list[Role],
        visited: set[RoleId],
        stack: set[RoleId],
        *,
        depth: int,
    ) -> None:
        self._require_depth(depth)
        if role.id in stack:
            raise RoleHierarchyCycle(role.id, role.id)
        if role.id in visited:
            return
        visited.add(role.id)
        resolved.append(role)
        next_stack = {*stack, role.id}
        for parent_id in sorted(role.parent_role_ids, key=str):
            parent = self._require_available(parent_id)
            self._validate_edge(role, parent)
            if parent.id in next_stack:
                raise RoleHierarchyCycle(role.id, parent.id)
            self._walk(parent, resolved, visited, next_stack, depth=depth + 1)

    def _find_permission(
        self,
        role: Role,
        permission: PermissionCode,
        stack: set[RoleId],
        *,
        depth: int,
    ) -> tuple[Role, ...] | None:
        self._require_depth(depth)
        if role.id in stack:
            raise RoleHierarchyCycle(role.id, role.id)
        if permission in role.permissions:
            return (role,)
        next_stack = {*stack, role.id}
        for parent_id in sorted(role.parent_role_ids, key=str):
            parent = self._require_available(parent_id)
            self._validate_edge(role, parent)
            if parent.id in next_stack:
                raise RoleHierarchyCycle(role.id, parent.id)
            path = self._find_permission(parent, permission, next_stack, depth=depth + 1)
            if path is not None:
                return (role, *path)
        return None

    def _require_available(self, role_id: RoleId) -> Role:
        role = self._roles.get(role_id)
        if role is None or role.status is not RoleStatus.ACTIVE:
            raise RoleHierarchyUnavailable(role_id)
        return role

    def _require_depth(self, depth: int) -> None:
        if depth > self._max_depth:
            raise RoleHierarchyDepthExceeded(self._max_depth)

    @staticmethod
    def _validate_edge(child: Role, parent: Role) -> None:
        if child.tenant_id is None and parent.tenant_id is not None:
            raise RoleHierarchyTenantMismatch(child.tenant_id, parent.tenant_id)
        if (
            child.tenant_id is not None
            and parent.tenant_id is not None
            and child.tenant_id != parent.tenant_id
        ):
            raise RoleHierarchyTenantMismatch(child.tenant_id, parent.tenant_id)


class RoleHierarchyApplicationService:
    """Mutate Role hierarchy while enforcing graph and tenant invariants."""

    def __init__(
        self,
        *,
        role_repository: RoleRepository,
        clock: Clock,
        event_sink: DomainEventSink,
        max_depth: int = 32,
    ) -> None:
        self._roles = role_repository
        self._clock = clock
        self._events = event_sink
        self._resolver = RoleHierarchyResolver(role_repository, max_depth=max_depth)

    def add_parent_role(self, role_id: RoleId, parent_role_id: RoleId) -> Role:
        role = self._require_role(role_id)
        parent = self._require_role(parent_role_id)
        RoleHierarchyResolver._validate_edge(role, parent)
        if role.id == parent.id or role.id in self._resolver.ancestor_ids(parent.id):
            raise RoleHierarchyCycle(role.id, parent.id)
        role.add_parent_role(parent.id, at=self._clock.now())
        return self._save_role(role)

    def remove_parent_role(self, role_id: RoleId, parent_role_id: RoleId) -> Role:
        role = self._require_role(role_id)
        role.remove_parent_role(parent_role_id, at=self._clock.now())
        return self._save_role(role)

    def _require_role(self, role_id: RoleId) -> Role:
        role = self._roles.get(role_id)
        if role is None:
            raise RoleNotFound(role_id)
        if role.status is not RoleStatus.ACTIVE:
            raise RoleHierarchyUnavailable(role_id)
        return role

    def _save_role(self, role: Role) -> Role:
        events = role.pull_events()
        self._roles.save(role)
        self._events.publish(events)
        saved = self._roles.get(role.id)
        if saved is None:
            raise RuntimeError("Role repository did not return the persisted aggregate.")
        return saved
