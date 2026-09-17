# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Audit + explainability beta (`0.2.0b2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.2.0b2` adds a dedicated **append-only Audit context** and hardens decision explainability while preserving the existing authorization API.

Every runtime decision now has a stable `AuthorizationDecisionId`. When an `AuditSink` is configured, both `ALLOW` and `DENY` decisions are synchronously projected to a minimal audit record containing identity, tenant, permission, reason and selected IAM references.

Resource attribute payloads are deliberately excluded from authorization audit records:

```text
AuthorizationDecision
       ↓
AuthorizationDecisionAuditRecorder
       ↓
AuditSink
       ↓
PostgreSQL / SIEM / Kafka / custom adapter
```

Decision explanation now supports two projections:

```python
summary = decision.explanation()
detailed = decision.explanation(ExplanationLevel.DETAILED)
```

`SUMMARY` exposes the result and reason without internal graph identifiers. `DETAILED` additionally exposes the diagnostic `explanation_path` and is intended for trusted administrative or debugging surfaces.

The existing `engine.explain(request)` API remains available. `engine.describe(request)` directly returns a safe explanation projection.

## Architecture

```text
AuthorizationRequest
       ↓
Identity + Tenant + Membership
       ↓
RoleBinding + Role Hierarchy
       ↓
candidate Permission
       ↓
Constraints + SoD
       ↓
AuthorizationDecision
       ├── DecisionExplanation
       │    ├── SUMMARY
       │    └── DETAILED
       └── AuthorizationDecisionAuditRecorder
              ↓
           AuditSink
```

The audit context is independent from Django, FastAPI, SQLAlchemy, Redis and any specific SIEM or messaging platform.

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
