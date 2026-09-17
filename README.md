# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Authorization-engine alpha (`0.2.0a1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.2.0a1` introduces the first **runtime Authorization Engine**. Direct RoleBindings are evaluated against active Identity, Tenant and Membership state, explicit TenantScope, active Roles and registered Permissions. Every request resolves to an explainable `ALLOW` or `DENY` decision.

```python
decision = engine.authorize(request)
allowed = engine.can(request)
engine.require(request)
```

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
active Role
       ↓
Permission
       ↓
AuthorizationDecision
(ALLOW / DENY + reason_code)
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

See the executable examples under `examples/`.

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
