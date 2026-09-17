# RoleBindings and Scoped RBAC

`0.1.0b2` introduces the association that was deliberately absent from the Roles & Permissions milestone.

```text
Identity
   ↓ active Membership
Tenant
   ↓
RoleBinding
   ├── Role
   └── TenantScope
```

A RoleBinding is created only when the Identity, Tenant and Membership are active, the Role is active and directly assignable, and the Role/Scope tenant boundaries are coherent.

A tenant-scoped Role defined for Tenant A cannot be assigned in Tenant B. A global Role (`tenant_id=None`) may be assigned inside a tenant, but still requires an active Membership and an explicit TenantScope.

The binding lifecycle supports suspension, reactivation, revocation and temporal expiry. The runtime AuthorizationEngine is intentionally deferred to `0.2.0a1`.
