# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Hierarchical-RBAC alpha (`0.2.0a2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.2.0a2` extends the runtime Authorization Engine with **Hierarchical RBAC**. A bound Role can inherit permissions transitively from parent Roles while the original RoleBinding remains the security boundary: inheritance never widens its TenantScope.

```text
RoleBinding(scope = Tenant A)
        ↓
TenantFinanceManager
        ↓ inherits
FinanceManager
        ↓ inherits
BaseReader
        ↓
Permission
```

A tenant Role may inherit a global Role. A global Role may not inherit a tenant Role, and Roles from different tenants cannot be linked. Cyclic, missing, disabled or over-deep hierarchies fail closed.

```python
decision = engine.authorize(request)
allowed = engine.can(request)
engine.require(request)
```

When a permission is inherited, `decision.bound_role_id` identifies the Role attached to the RoleBinding and `decision.matched_role_id` identifies the ancestor Role that contributed the matching Permission.

## Architecture

```text
AuthorizationRequest
       ↓
Identity + Tenant + Membership
       ↓
active RoleBindings
       ↓
TenantScope
       ↓
bound Role
       ↓
Role Hierarchy (DAG)
       ↓
direct / inherited Permission
       ↓
AuthorizationDecision
(ALLOW / DENY + reason_code + explanation_path)
```

The core remains independent from Django, FastAPI, SQLAlchemy, Redis and external identity providers.

## Quickstart

Python 3.12+ is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install build mypy pytest pytest-cov ruff
make check
```

See the executable examples under `examples/` and architecture notes under `docs/architecture/`.

## Roadmap

```text
0.0.1      Repository bootstrap
0.1.0a1    Identity domain
0.1.0a2    Tenancy / Membership
0.1.0b1    Roles & Permissions
0.1.0b2    RoleBindings + Scoped RBAC
0.2.0a1    Authorization Engine
0.2.0a2    Hierarchical RBAC
0.2.0b1    Constraints + Separation of Duties
0.2.0b2    Audit + decision explainability hardening
0.3.x      Persistence, sessions, credentials, JWT, FastAPI
0.4.x      Federation, MFA, Django, SCIM
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
