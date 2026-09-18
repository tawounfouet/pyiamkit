# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, auditability and durable persistence.

> **Status:** MFA step-up beta (`0.4.0b1`) — not yet recommended for production use.

## Goals

PyIAMKit is designed around default deny, least privilege, explicit tenant/scope boundaries, explainable authorization, strong revocation and framework-independent domain logic.

## Current milestone

`0.4.0b1` adds **TOTP MFA enrollment and Session step-up** without storing raw OTP secrets in the IAM database.

```text
active Identity
      ↓
begin TOTP enrollment
      ↓
external MfaSecretStore
      ├── raw secret
      └── provisioning URI
      ↓
MfaFactor(PENDING)
      ↓
first valid code
      ↓
MfaFactor(ACTIVE)
      ↓
AAL1 Session
      +
valid unused TOTP
      ↓
Session.step_up()
      ↓
AAL2 + mfa=true
      ↓
reissue access JWT
```

The persisted MFA factor stores only an opaque `secret_reference`. The PyOTP adapter resolves the secret through an injected store.

A successful TOTP counter is recorded and cannot be replayed. TOTP step-up raises local assurance to **AAL2**, not AAL3.

Because JWT verification cross-checks durable Session assurance, an access token issued before step-up becomes invalid immediately after the Session changes from AAL1/MFA=false to AAL2/MFA=true. The application then issues a fresh token.

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

## MFA step-up guarantees in 0.4.0b1

- TOTP secret material is kept behind `MfaSecretStore`;
- database persistence stores only opaque secret references;
- factors require first-code confirmation before becoming active;
- accepted TOTP counters cannot be replayed;
- factor/session Identity ownership is enforced;
- revoked factors cannot be used for step-up;
- TOTP elevates a Session to AAL2 at most;
- local MFA verification time and factor ID are persisted;
- stale pre-step-up JWTs fail the existing Session-state cross-check;
- PyOTP remains optional and outside the Authentication core.

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
