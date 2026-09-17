# Roles and Permissions

`0.1.0b1` introduces the RBAC catalog without assigning rights to identities yet.

A `Permission` is a stable capability code such as `invoice.read` or `iam.role.assign`.
A `Role` is a named collection of permission codes.

```text
Role
  ↓ contains
Permission
```

There is intentionally no `Subject`, `Identity` or `Membership` association in this milestone. That association belongs to `RoleBinding` and will be introduced in `0.1.0b2`.

Roles may be global (`tenant_id=None`) or explicitly tenant-scoped. Role-name uniqueness is evaluated within that namespace.

Sensitive and non-assignable roles are represented explicitly so later authorization and governance layers can enforce stronger controls.
