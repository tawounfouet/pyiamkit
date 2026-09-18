# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** Assurance-aware authorization beta (`0.4.0b2`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0b2` connects **authentication assurance to authorization policy** without coupling the Authorization Engine to Authentication Session persistence.

```text
RBAC candidate ALLOW
        ↓
MinimumAssuranceConstraint
        ↓
AuthenticationEvidence
   ├── AAL
   ├── MFA
   └── authenticated_at
        ↓
sufficient?
   ├── yes → ALLOW
   └── no  → DENY_STEP_UP_REQUIRED
                  ↓
                  MFA / re-authentication
                  ↓
                  new AAL/MFA evidence
                  ↓
                  retry authorization
```

The rule is restrictive only: assurance can reduce an existing RBAC candidate ALLOW, but it can never create a permission.

Example policy:

```python
governance.register_minimum_assurance(
    "payment.approve",
    minimum_assurance=AssuranceLevel.AAL2,
    require_mfa=True,
    tenant_id=tenant_id,
)
```

Authorization callers provide a snapshot rather than a Session repository:

```python
AuthenticationEvidence(
    assurance_level=AssuranceLevel.AAL2,
    mfa=True,
    authenticated_at=authenticated_at,
)
```

If required evidence is missing, evaluation fails closed. If evidence is present but insufficient, the decision exposes `step_up_required=True` and the required AAL/MFA.

FastAPI builds the evidence from already verified access-token claims. A step-up requirement remains HTTP 403, while missing/invalid bearer authentication remains HTTP 401.

## Installation

Python 3.12+ is required.

Core only:

```bash
python -m pip install -e .
```

SQLAlchemy persistence with SQLite or another SQLAlchemy-supported backend:

```bash
python -m pip install -e ".[sqlalchemy]"
```

PostgreSQL persistence with psycopg:

```bash
python -m pip install -e ".[postgres]"
```

JWT access-token adapter:

```bash
python -m pip install -e ".[jwt]"
```

OIDC federation adapter with configured keys:

```bash
python -m pip install -e ".[oidc]"
```

OIDC Discovery + remote JWKS:

```bash
python -m pip install -e ".[oidc-http]"
```

TOTP MFA:

```bash
python -m pip install -e ".[mfa]"
```

FastAPI integration:

```bash
python -m pip install -e ".[fastapi]"
```

FastAPI + JWT:

```bash
python -m pip install -e ".[jwt,fastapi]"
```

Development checks:

```bash
python -m pip install build mypy pytest pytest-cov ruff
make check
```

See executable examples under `examples/` and architecture notes under `docs/architecture/`.

## Architecture

```text
Identity
   │
   ├── CredentialRepository
   │      └── Credential
   │          ├── opaque secret reference
   │          ├── type / fingerprint
   │          └── validity / revocation
   │
   └── SessionRepository
          └── Session
              ├── AuthenticationContext
              │    ├── method
              │    ├── assurance level
              │    ├── MFA state
              │    └── provider/device/network
              ├── expiration
              └── revocation

Authentication context
       ↓
AuthorizationRequest / host application context
       ↓
AuthorizationEngine
       ↓
AuthorizationDecision + Audit
```

The Authentication domain does not import SQLAlchemy, psycopg, JWT libraries, FastAPI, Django or an external IdP SDK. Persistence and future token/federation integrations depend inward on Authentication contracts.

## Assurance-aware authorization guarantees in 0.4.0b2

- Authorization never loads or mutates Authentication Sessions;
- authentication evidence is explicit input to `AuthorizationRequest`;
- minimum assurance rules are deny-only governance constraints;
- missing authentication evidence fails closed when required;
- insufficient AAL produces a structured step-up-required decision;
- MFA requirements are evaluated independently from AAL;
- required assurance/MFA are included in decision audit metadata;
- FastAPI forwards only verified token claims into authorization;
- ordinary authorization deny remains 403 Forbidden;
- step-up-required is also 403, with structured challenge metadata;
- authentication failures remain 401 with `WWW-Authenticate: Bearer`.

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
0.3.0a1    SQLAlchemy / SQLite / PostgreSQL persistence
0.3.0a2    Sessions + Credentials
0.3.0b1    JWT
0.3.0b2    FastAPI integration
0.4.0a1    OIDC federation core + static-key ID Token verification
0.4.0a2    OIDC Discovery / JWKS cache and rotation
0.4.0b1    MFA enrollment / TOTP step-up
0.4.0b2    Assurance-aware authorization / step-up requirements
0.4.x      Django, SCIM and provider integrations
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
