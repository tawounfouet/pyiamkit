# MFA Enrollment & Session Step-Up — 0.4.0b1

## Purpose

`0.4.0b1` adds local multi-factor enrollment and assurance step-up to PyIAMKit.

The first supported local factor is TOTP.

The milestone preserves the separation:

```text
Identity
   ↓
MFA enrollment
   ↓
MfaFactor
   ↓
MfaSecretStore
   ↓
TOTP verification
   ↓
Session assurance step-up
   ↓
JWT reissuance
   ↓
Authorization
```

MFA proves additional authentication evidence. It does not grant Roles or Permissions by itself.

## Core guarantees

- MFA factor lifecycle is explicit.
- Pending enrollment cannot authenticate.
- Raw TOTP secrets stay outside the IAM database.
- A used TOTP counter cannot be accepted again.
- Factors are bound to one Identity.
- A factor cannot elevate another Identity's Session.
- TOTP raises local assurance to AAL2 at most.
- Step-up state is durable in Session.
- Old access JWTs fail after Session assurance changes.

## Domain model

```text
MfaFactor
├── id
├── identity_id
├── type = TOTP
├── status
│   ├── PENDING
│   ├── ACTIVE
│   └── REVOKED
├── secret_reference
├── label?
├── created_at
├── updated_at
├── activated_at?
├── revoked_at?
├── last_verified_at?
└── last_accepted_counter?
```

The factor contains no raw OTP secret.

## Enrollment lifecycle

```text
begin enrollment
      ↓
secret created in MfaSecretStore
      ↓
MfaFactor(PENDING)
      ↓
user scans provisioning URI
      ↓
first TOTP code
      ├── invalid → remain PENDING
      ↓ valid
counter persisted
      ↓
MfaFactor(ACTIVE)
```

A provisioning URI necessarily contains enrollment secret material and must be treated as sensitive one-time setup data by the host application.

## Secret boundary

Core contract:

```python
class MfaSecretStore(Protocol):
    def put(self, reference: str, secret: str) -> None: ...
    def get(self, reference: str) -> str | None: ...
    def delete(self, reference: str) -> None: ...
```

Persisted factor data contains only:

```text
mfa://totp/<factor-id>
vault://...
kms-backed-reference://...
```

Production systems should implement this port using their secret-management platform.

The bundled `InMemoryMfaSecretStore` is for tests and executable examples only.

## TOTP provider

The optional adapter is:

```text
pyiamkit.authentication.adapters.totp.PyOtpTotpProvider
```

Install with:

```bash
python -m pip install "pyiamkit[mfa]"
```

Configuration:

```text
issuer_name
digits = 6 or 8
interval > 0
valid_window >= 0
MfaSecretStore
```

PyIAMKit delegates TOTP generation and constant-time code comparison to PyOTP rather than implementing OTP cryptography itself.

## Replay prevention

A TOTP code is associated with a time counter.

The factor persists:

```text
last_accepted_counter
```

A new verification must satisfy:

```text
matched_counter > last_accepted_counter
```

Therefore the same accepted counter cannot be replayed, even if it remains within a configured clock-skew window.

## Session step-up

Before:

```text
Session
├── assurance = AAL1
├── mfa = false
├── mfa_verified_at = null
└── mfa_factor_id = null
```

After valid TOTP step-up:

```text
Session
├── assurance = AAL2
├── mfa = true
├── mfa_verified_at = now
└── mfa_factor_id = verified factor
```

The original authentication method and original `authenticated_at` remain intact.

This records that the Session was initially established one way and later strengthened.

## Assurance ceiling

TOTP step-up targets:

```text
AAL2
```

It cannot downgrade a Session already at a stronger level.

It also cannot claim AAL3.

Future phishing-resistant factors can introduce stronger assurance policies separately.

## JWT interaction

PyIAMKit's JWT adapter already cross-checks:

- Session subject;
- Session assurance level;
- Session MFA state;
- authentication method;
- authentication time.

Example:

```text
T0 Session = AAL1 / MFA false
T1 JWT-A issued with AAL1 / MFA false
T2 TOTP step-up
T3 Session = AAL2 / MFA true
T4 JWT-A verified
      ↓
claims do not match Session
      ↓
DENY
T5 JWT-B issued from elevated Session
T6 JWT-B verifies
```

No access-token blacklist is needed for this transition.

## Persistence

SQLAlchemy adds:

```text
iam_mfa_factors
```

Important columns:

```text
id
identity_id
factor_type
status
secret_reference
label
created_at
updated_at
activated_at
revoked_at
last_verified_at
last_accepted_counter
```

Session persistence adds:

```text
mfa_verified_at
mfa_factor_id
```

The factor ID is a foreign key to the MFA factor table.

## Application service

`MfaApplicationService` exposes:

```text
begin_totp_enrollment()
confirm_totp_enrollment()
verify_totp()
step_up_totp_session()
revoke_factor()
factors_for_identity()
active_factors_for_identity()
```

Security preconditions include:

- active Identity required for enrollment;
- pending factor required for confirmation;
- active factor required for verification;
- active Session required for step-up;
- factor Identity must equal Session Identity.

## Revocation

Factor revocation is durable first.

After persistence marks the factor REVOKED, the service asks the configured TOTP provider to remove referenced secret material.

If secret deletion fails, the factor remains revoked and therefore unusable.

This preserves fail-closed authentication semantics.

## Events

New domain events:

```text
MfaFactorCreated
MfaFactorActivated
MfaFactorVerified
MfaFactorRevoked
SessionSteppedUp
```

These can be projected into the existing audit infrastructure by the shared domain-event bridge.

## Tests

The milestone qualifies:

- pending enrollment;
- invalid first code;
- successful first-code activation;
- replay rejection;
- next-counter acceptance;
- factor/session ownership enforcement;
- factor revocation and secret deletion;
- AAL1 → AAL2 Session step-up;
- persistence of factor counter state;
- persistence of Session MFA context;
- stale JWT rejection after step-up;
- fresh JWT success after step-up;
- SQLite conformance;
- live PostgreSQL round-trip;
- Python 3.12 and 3.13;
- mypy strict;
- Ruff;
- Bandit.

## Explicit non-goals

`0.4.0b1` does not yet implement:

- WebAuthn enrollment;
- push MFA;
- SMS or email OTP;
- recovery codes;
- backup-factor policy;
- recent-auth age constraints;
- mandatory MFA policy per Permission;
- account-recovery workflow;
- factor attestation;
- adaptive/risk-based MFA.

These can build on the same factor and Session assurance contracts.

## Next direction

The next milestone can connect authorization requirements to authentication assurance:

```text
Permission / policy
      ↓
requires AAL2?
      ↓
Session AAL1
      ↓
step-up required
      ↓
MFA
      ↓
retry authorization with elevated Session
```

This keeps step-up enforcement explicit rather than hiding it inside framework middleware.
