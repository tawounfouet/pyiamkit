# Authorization Engine — 0.2.0a1

`0.2.0a1` introduces the first runtime authorization decision engine.

## Supported model

The engine evaluates direct scoped RBAC only:

```text
Identity
  ↓ active
Membership
  ↓ active in Tenant
RoleBinding
  ↓ active + TenantScope
Role
  ↓ active
Permission
  ↓ registered
AuthorizationDecision
```

The engine is **default deny**. An `ALLOW` exists only when every required invariant is proven and an active Role contains the requested Permission.

## Evaluation order

1. Subject exists.
2. Subject is active.
3. Tenant exists.
4. Tenant is active.
5. Active Membership exists for Subject + Tenant.
6. Permission is registered in the catalog.
7. Active RoleBindings exist for Subject + Tenant.
8. A RoleBinding matches the requested TenantScope.
9. Every matching Role resolves to an active, tenant-compatible Role.
10. At least one matching Role contains the requested Permission.
11. Otherwise return a structured `DENY`.

## Public API

```python
decision = engine.authorize(request)
allowed = engine.can(request)
decision = engine.require(request)  # raises AuthorizationDenied on DENY
decision = engine.explain(request)
```

Every decision exposes:

- `result`
- `reason_code`
- `subject_id`
- `tenant_id`
- `permission`
- `scope`
- `evaluated_at`
- matched Role/RoleBinding identifiers when allowed
- correlation identifier
- `explanation_path`

## Deliberate exclusions

The following are not part of `0.2.0a1`:

- Role hierarchy
- Group-derived roles
- Policy conditions / ABAC
- Separation of Duties
- Delegation
- MFA / assurance constraints
- resource attributes
- distributed authorization caches

These layers must extend the evaluation pipeline without weakening default-deny semantics.
