# Hierarchical RBAC — 0.2.0a2

`0.2.0a2` adds transitive Role inheritance to PyIAMKit.

## Semantics

```text
RoleBinding(scope = Tenant A)
        ↓
TenantManager
        ↓ inherits
FinanceManager
        ↓ inherits
BaseReader
        ↓
Permission
```

The RoleBinding remains the authorization boundary. Inheritance expands the permission set of the bound Role; it never widens the binding scope.

## Invariants

- Role hierarchy is acyclic.
- Traversal depth is bounded.
- Missing or disabled parent Roles make the hierarchy unavailable and therefore fail closed.
- A tenant Role may inherit a global Role.
- A global Role may not inherit a tenant Role.
- A Role in Tenant A may not inherit a Role in Tenant B.
- Direct and inherited permission matches are distinguishable in `AuthorizationDecision.reason_code`.
- `bound_role_id` identifies the Role referenced by the RoleBinding.
- `matched_role_id` identifies the Role that actually contributes the matching Permission.

## Resolution

`RoleHierarchyResolver` exposes:

```text
ancestor_ids(role_id)
resolve_roles(role_id)
effective_permissions(role_id)
permission_path(role_id, permission)
```

`RoleHierarchyApplicationService` owns hierarchy mutations and performs cycle and tenant checks before persistence.
