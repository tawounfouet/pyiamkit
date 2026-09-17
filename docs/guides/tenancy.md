# Tenancy and Membership

PyIAMKit treats a Tenant as a security boundary, not as a simple data-filter column.

An Identity is global. Access to a Tenant requires an explicit active Membership.

```text
Identity
  ↓
Membership
  ↓
Tenant
```

The `TenancyApplicationService.resolve_context()` operation validates the Identity, Tenant and Membership before producing a `TenantContext`.

A membership in Tenant A never establishes a context for Tenant B.

## Alpha example

```python
context = tenancy.resolve_context(
    identity_id=alice.id,
    tenant_id=acme.id,
)
```

`TenantScope`, `TenantContext` and `TenantIsolationGuard` are introduced in `0.1.0a2` as the first explicit multi-tenant security primitives.
