# Assurance-Aware Authorization — 0.4.0b2

## Purpose

Version 0.4.0b2 connects Authentication assurance to the existing deny-only Authorization governance layer.

~~~text
RBAC / hierarchy
      ↓
candidate ALLOW
      ↓
governance constraints
      ↓
final ALLOW or DENY
~~~

A minimum-assurance rule can only restrict a candidate permission. It can never create one.

## Architectural boundary

Authorization does not depend on a Session repository. The application supplies an immutable AuthenticationEvidence snapshot:

~~~text
AuthenticationEvidence
├── assurance_level
├── mfa
└── authenticated_at
~~~

This prevents hidden Session I/O inside authorization, authorization-side mutation of authentication state, and framework-specific Session coupling.

~~~text
Authentication
     ↓
verified evidence
     ↓
AuthorizationRequest
     ↓
AuthorizationEngine
~~~

## MinimumAssuranceConstraint

A rule is bound to a Permission and optionally to a Tenant:

~~~python
MinimumAssuranceConstraint(
    id=rule_id,
    permission=PermissionCode("payment.approve"),
    minimum_assurance=AssuranceLevel.AAL2,
    require_mfa=True,
    tenant_id=tenant_id,
)
~~~

It is part of the existing AuthorizationConstraint union and is evaluated only after a candidate RBAC permission path has matched.

## Evaluation semantics

~~~text
RBAC candidate ALLOW
       ↓
authentication evidence present?
       ├── no → DENY_AUTHENTICATION_CONTEXT_MISSING
       ↓ yes
AAL >= required AAL?
       ├── no → DENY_STEP_UP_REQUIRED
       ↓ yes
MFA required?
       ├── yes + evidence.mfa=false → DENY_STEP_UP_REQUIRED
       ↓
ALLOW
~~~

Missing evidence is distinct from insufficient evidence. Missing evidence is a fail-closed integration/security-context failure. Insufficient evidence is actionable and can trigger step-up.

## Step-up-required decision

When current evidence is insufficient, AuthorizationDecision remains a DENY and carries:

~~~text
reason_code = DENY_STEP_UP_REQUIRED
step_up_required = true
required_assurance_level = AAL2
required_mfa = true
~~~

The host application may perform MFA or re-authentication and then retry the original authorization request.

## Assurance ordering

PyIAMKit uses the existing local assurance ordering:

~~~text
AAL1 < AAL2 < AAL3
~~~

A stronger assurance satisfies a lower minimum. MFA is evaluated independently from AAL: a high AAL value does not automatically imply MFA unless the supplied evidence says so.

## Governance registration

AccessGovernanceApplicationService exposes:

~~~python
governance.register_minimum_assurance(
    "payment.approve",
    minimum_assurance=AssuranceLevel.AAL2,
    require_mfa=True,
    tenant_id=tenant_id,
)
~~~

No second policy engine is introduced.

## Persistence

The existing iam_constraints table adds support for:

~~~text
kind = minimum_assurance
minimum_assurance
require_mfa
~~~

resource_attribute becomes optional because assurance rules do not require a business-resource attribute.

SQLite and PostgreSQL use the same repository contract.

## Audit

Authorization decision audit metadata may include:

~~~text
matched_rule_id
required_assurance_level
required_mfa
~~~

Audit does not include bearer tokens, MFA codes, factor secrets, secret references, Session objects, or resource attribute payloads.

## JWT and Session composition

The JWT adapter already verifies aal and mfa claims against durable Session state. FastAPI converts the verified claims into AuthenticationEvidence.

~~~text
Session AAL1 / MFA=false
       ↓
JWT A
       ↓
RBAC candidate ALLOW
       ↓
MinimumAssuranceConstraint(AAL2, MFA=true)
       ↓
DENY_STEP_UP_REQUIRED
       ↓
TOTP MFA
       ↓
Session AAL2 / MFA=true
       ↓
old JWT A fails Session cross-check
       ↓
new JWT B
       ↓
AuthenticationEvidence(AAL2, MFA=true)
       ↓
retry authorization
       ↓
ALLOW
~~~

This composes 0.4.0b1 and 0.4.0b2 without making Authorization aware of Session persistence.

## FastAPI semantics

Authentication failures remain HTTP 401 with WWW-Authenticate: Bearer.

Ordinary authorization denial remains:

~~~json
{
  "detail": "Forbidden"
}
~~~

Step-up-required remains HTTP 403 because the caller is already authenticated:

~~~json
{
  "detail": {
    "code": "step_up_required",
    "required_assurance_level": "aal2",
    "required_mfa": true
  }
}
~~~

## Security properties

- default deny remains unchanged;
- RBAC remains necessary before assurance can permit anything;
- missing evidence fails closed;
- assurance constraints are Permission- and Tenant-aware;
- MFA is not inferred from AAL;
- AAL is not inferred from MFA;
- AuthorizationEngine never loads or mutates Authentication Sessions;
- required assurance metadata is auditable without credential material;
- the rule is restrictive only.

## Qualification

The release qualifies:

- no evidence -> fail closed;
- AAL1 against AAL2 -> step-up required;
- AAL2 without required MFA -> step-up required;
- AAL2 plus MFA -> existing RBAC candidate ALLOW;
- SQLite constraint round-trip;
- live PostgreSQL persisted constraint;
- FastAPI verified JWT evidence propagation;
- structured FastAPI step-up response;
- Python 3.12 and 3.13;
- mypy strict;
- Ruff;
- coverage;
- build/wheel/smoke/examples;
- Bandit.

## Non-goals

This release does not yet add maximum authentication age, maximum MFA age, risk scoring, device trust, WebAuthn-specific assurance rules, or automatic MFA orchestration inside AuthorizationEngine.

Those can extend AuthenticationEvidence and the deny-only governance model without changing bounded-context ownership.
