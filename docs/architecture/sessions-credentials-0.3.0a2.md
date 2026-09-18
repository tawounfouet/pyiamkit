# Sessions + Credentials — 0.3.0a2

## Purpose

`0.3.0a2` introduces the first framework-neutral Authentication bounded context in PyIAMKit.

The milestone intentionally separates three questions:

```text
Identity        Who is the subject?
Authentication How was the subject authenticated, and with what assurance?
Authorization  What may the authenticated subject do?
```

An authenticated subject is not automatically authorized. A valid Credential or Session never grants a Role or Permission by itself.

## Design goals

The Authentication context must:

- remain independent from Django, FastAPI and any web framework;
- remain independent from JWT, OAuth2, OIDC and SAML token formats;
- never own raw password, API-key or client-secret material;
- model revocation and expiration explicitly;
- preserve authentication assurance for later authorization decisions;
- support human and machine identities;
- persist through the same repository-port architecture as existing bounded contexts;
- fail closed when identity state or temporal validity is not acceptable.

## Bounded-context position

```text
                    ┌──────────────────┐
                    │     Identity     │
                    │ stable subject   │
                    └────────┬─────────┘
                             │
                 active Identity required
                             │
                             ▼
                    ┌──────────────────┐
                    │ Authentication   │
                    │                  │
                    │ Credential       │
                    │ Session          │
                    │ Auth Context     │
                    └────────┬─────────┘
                             │
                   authenticated context
                             │
                             ▼
                    ┌──────────────────┐
                    │ Authorization    │
                    │ RBAC / SoD /     │
                    │ constraints      │
                    └────────┬─────────┘
                             │
                             ▼
                    AuthorizationDecision
```

The Authentication package depends on Identity identifiers and repository contracts. Authorization does not become a dependency of Authentication.

## Credential aggregate

A `Credential` represents metadata around an authentication capability.

Core state:

```text
Credential
├── id
├── identity_id
├── type
├── status
├── reference
├── fingerprint?
├── label?
├── valid_from
├── valid_until?
├── revoked_at?
├── metadata
├── created_at / updated_at
└── version
```

### Secret boundary

`Credential.reference` is deliberately an opaque reference, for example:

```text
vault://iam/credentials/alice/password
aws-secretsmanager://prod/api-key/service-42
azure-keyvault://iam/client-secret/billing-worker
passkey://registry/alice/device-1
```

It is **not** the raw password, API key, private key or client secret.

Secret material belongs behind dedicated secret-management or credential-provider ports in later milestones.

The persistence schema therefore has no generic `secret`, `password`, `api_key_value` or `private_key` column.

### Credential types

```text
PASSWORD
API_KEY
CERTIFICATE
PASSKEY
CLIENT_SECRET
EXTERNAL
```

These values classify authentication capability. They do not imply how the secret is verified.

### Credential lifecycle

```text
        create
          │
          ▼
       ACTIVE
        /   \
   revoke   expire
      │       │
      ▼       ▼
   REVOKED  EXPIRED
```

Revocation and expiration are terminal in this alpha model.

An active Credential must satisfy:

```text
status == ACTIVE
AND at >= valid_from
AND (valid_until IS NULL OR at < valid_until)
```

## AuthenticationContext

`AuthenticationContext` records the evidence attached to an established authentication.

```text
AuthenticationContext
├── method
├── assurance_level
├── mfa
├── authenticated_at
├── provider_id?
├── device_id?
└── network_zone?
```

Supported authentication methods:

```text
PASSWORD
API_KEY
CERTIFICATE
PASSKEY
OIDC
SAML
EXTERNAL
```

The context is intentionally token-format agnostic.

## Assurance levels

PyIAMKit exposes three internal assurance values:

```text
AAL1
AAL2
AAL3
```

They are framework-neutral domain values. They are not a claim that PyIAMKit independently certifies compliance with any external assurance standard.

An adapter may map an external provider's assurance information into these values only after the adapter validates the provider-specific evidence.

Example future authorization use:

```text
permission = payment.approve
candidate RBAC allow = true
required assurance = AAL2
session assurance = AAL1
--------------------------------
decision = DENY / STEP-UP REQUIRED
```

Step-up policy enforcement remains a later policy/authentication integration milestone.

## Session aggregate

A `Session` represents a revocable authenticated session.

Core state:

```text
Session
├── id
├── identity_id
├── status
├── AuthenticationContext
├── created_at
├── updated_at
├── expires_at
├── last_activity_at
├── revoked_at?
├── revocation_reason?
└── version
```

Lifecycle:

```text
          open
           │
           ▼
        ACTIVE
       /   |   \
  touch  revoke expire
    │      │      │
    └──────┘      │
           ▼      ▼
        REVOKED EXPIRED
```

A Session is active only when:

```text
status == ACTIVE
AND at < expires_at
```

A touch operation cannot move session activity backwards in time.

## Application service

`AuthenticationApplicationService` coordinates the aggregates with existing Identity state.

Operations:

```text
register_credential()
revoke_credential()
expire_credential()
active_credentials()

open_session()
touch_session()
revoke_session()
expire_session()
revoke_all_sessions()
active_sessions()
```

Security prerequisites:

1. Credential registration requires an existing active Identity.
2. Session creation requires an existing active Identity.
3. Credential references are globally unique in the current repository contract.
4. Bulk revocation touches only currently active sessions.
5. Domain events are persisted through the shared `DomainEventSink` boundary.

## Repository ports

Authentication exposes two repository protocols:

```text
CredentialRepository
├── get
├── save
├── find_by_reference
├── find_for_identity
└── find_active_for_identity

SessionRepository
├── get
├── save
├── find_for_identity
└── find_active_for_identity
```

Reference InMemory adapters establish expected semantics.

SQLAlchemy adapters implement the same ports without committing application transactions.

## SQLAlchemy persistence

The persistence layer adds:

```text
iam_credentials
iam_sessions
```

### iam_credentials

Important columns:

```text
id UUID PK
identity_id UUID FK -> iam_identities
credential_type
status
reference UNIQUE
fingerprint nullable
label nullable
created_at / updated_at
valid_from / valid_until
revoked_at nullable
metadata_json JSON / JSONB
```

Database constraints reinforce temporal validity.

### iam_sessions

Important columns:

```text
id UUID PK
identity_id UUID FK -> iam_identities
status
authentication_method
assurance_level
mfa
authenticated_at
provider_id nullable
device_id nullable
network_zone nullable
created_at / updated_at
expires_at
last_activity_at
revoked_at nullable
revocation_reason nullable
```

The table contains no bearer token or refresh token material.

## Transaction ownership

As in `0.3.0a1`, repositories receive a caller-owned SQLAlchemy `Session`.

```python
with SessionFactory.begin() as db:
    credentials = SqlAlchemyCredentialRepository(db)
    sessions = SqlAlchemySessionRepository(db)

    credentials.save(credential)
    sessions.save(session)
    # host transaction commits here
```

Repository methods do not call `commit()`.

## Revocation model

Revocation is immediate at the repository/domain layer.

```text
Identity
  ├── Credential A -> REVOKED
  ├── Credential B -> ACTIVE
  │
  ├── Session 1 -> REVOKED
  ├── Session 2 -> REVOKED
  └── Session 3 -> EXPIRED
```

`revoke_all_sessions(identity_id)` provides the first account-wide session invalidation primitive.

Distributed cache invalidation and token revocation are not yet implemented.

## Explicit non-goals for 0.3.0a2

This milestone does not implement:

- password hashing or password verification;
- raw secret storage;
- JWT access or refresh tokens;
- refresh-token rotation;
- token-family reuse detection;
- OAuth2 authorization flows;
- OIDC provider validation;
- SAML assertion validation;
- MFA enrollment or factor verification;
- WebAuthn protocol handling;
- account recovery;
- SCIM;
- distributed session cache;
- Redis revocation;
- browser cookies or CSRF controls.

Those capabilities must remain adapters or later bounded capabilities rather than leaking into the current domain model.

## Testing strategy

Qualification covers:

```text
Domain unit tests
    ↓
Application-service tests
    ↓
Repository conformance
    ├── InMemory
    └── SQLAlchemy / SQLite
             ↓
Live PostgreSQL 16 integration
             ↓
Build / wheel / smoke / examples
             ↓
Bandit
```

Key scenarios include:

- invalid temporal windows rejected;
- inactive Identity rejected;
- duplicate Credential reference rejected;
- Credential revocation/expiration;
- Session touch/revocation/expiration;
- bulk session revocation;
- AuthenticationContext round-trip;
- active-query filtering;
- SQL transaction rollback;
- PostgreSQL persistence across a new SQLAlchemy Session.

## Version integrity

`0.3.0a2` also closes a release-engineering gap discovered after `0.3.0a1`: package metadata and `pyiamkit.__version__` had diverged.

The smoke test now validates:

```text
importlib.metadata.version("pyiamkit")
==
pyiamkit.__version__
```

This makes version drift a CI failure.

## Next milestone

`0.3.0b1 — JWT` can now be implemented as an adapter over stable Authentication concepts:

```text
Credential / external authentication
        ↓
AuthenticationContext
        ↓
Session
        ↓
TokenProvider
        ↓
JWT access / refresh tokens
```

JWT must not become the source of truth for session lifecycle or authorization state.
