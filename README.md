# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Beta foundation (`0.1.0b2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.1.0b2` introduces **RoleBindings + Scoped RBAC**. An active Identity with an active Membership can now receive an active, assignable Role inside an explicit TenantScope. Tenant-scoped roles cannot cross tenant boundaries.

The actual runtime decision engine (`authorize`, `can`, `require`) arrives in `0.2.0a1`.

## Architecture

```text
Identity
   ↓
Membership
   ↓
Tenant
   ↓
RoleBinding
   ├── Role
   │    └── Permission
   └── TenantScope
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
0.2.x      Hierarchy, policies, SoD, delegation
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
