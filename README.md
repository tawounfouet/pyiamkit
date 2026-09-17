# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Constraints + SoD beta (`0.2.0b1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.2.0b1` adds **restrictive authorization constraints and Separation of Duties** on top of scoped Hierarchical RBAC. RBAC must first prove that the subject has a candidate permission; governance rules can then reduce that candidate authorization to `DENY`, but they never create access on their own.

```text
Identity + Tenant + Membership
          ↓
RoleBinding + Role Hierarchy
          ↓
candidate Permission
          ↓
Static SoD
          ↓
Dynamic SoD
          ↓
Resource Constraints
          ↓
AuthorizationDecision
```

A framework-neutral `ResourceDescriptor` carries the resource context required by runtime rules:

```python
resource = ResourceDescriptor(
    "payment",
    "PAY-001",
    tenant_id,
    attributes={
        "amount": "42000",
        "status": "pending",
        "prepared_by": str(preparer_id),
    },
)
```

Built-in examples now include numeric ceilings, required resource-attribute values, mutually exclusive effective Roles, and maker-checker rules such as `prepared_by != current subject`. Missing required rule context fails closed.

Static SoD is checked before a RoleBinding is persisted and includes inherited Roles, preventing a hierarchy from bypassing a mutually exclusive-role rule.

## Architecture

```text
AuthorizationRequest
       ↓
Identity + Tenant + Membership
       ↓
active RoleBindings + TenantScope
       ↓
Role Hierarchy (DAG)
       ↓
candidate Permission
       ↓
restrictive Governance Rules
       ├── Static SoD
       ├── Dynamic SoD
       └── Resource Constraints
       ↓
AuthorizationDecision
(ALLOW / DENY + reason_code + matched_rule_id + explanation_path)
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

See executable examples under `examples/` and architecture notes under `docs/architecture/`.

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
