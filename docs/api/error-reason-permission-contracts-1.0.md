# Error, Reason-Code and Permission Contracts — 1.0

## Public error contract

Every public exception exposed by the 1.0 freeze has a stable uppercase
snake-case `code` attribute.

The API Compatibility semantic audit enforces:

```text
code is present
code is a non-empty canonical uppercase token
code is unique across distinct public exception classes
```

Examples of stable families include:

```text
IDENTITY_*
TENANT_* / MEMBERSHIP_*
AUTHORIZATION_* / ROLE_* / PERMISSION_*
AUTHENTICATION_* / SESSION_* / CREDENTIAL_* / MFA_*
TOKEN_* / ACCESS_TOKEN_*
FEDERATION_* / OIDC_*
RATE_LIMIT_*
PROVISIONING_* / SCIM_*
PERSISTENCE_* / SCHEMA_MIGRATION_*
AUTHORIZATION_RUNTIME_* / OPERATIONAL_* / REVOCATION_*
DJANGO_AUTHENTICATION_REQUIRED
CONFORMANCE_FAILURE
```

Consumers should branch on the documented code/class rather than parse exception
messages.

## AuthorizationReason contract

`AuthorizationReason` is a public, stable decision reason enum.

Every value is equal to its enum name and is prefixed with `ALLOW_` or `DENY_`.

The frozen RC includes:

```text
ALLOW_INHERITED_ROLE_PERMISSION_MATCH
ALLOW_ROLE_PERMISSION_MATCH
DENY_AUTHENTICATION_CONTEXT_MISSING
DENY_CONSTRAINT_CONTEXT_MISSING
DENY_CONSTRAINT_VIOLATION
DENY_STEP_UP_REQUIRED
DENY_MEMBERSHIP_NOT_FOUND
DENY_NO_ACTIVE_BINDING
DENY_PERMISSION_NOT_GRANTED
DENY_PERMISSION_NOT_REGISTERED
DENY_ROLE_HIERARCHY_INVALID
DENY_ROLE_TENANT_MISMATCH
DENY_ROLE_UNAVAILABLE
DENY_SCOPE_MISMATCH
DENY_SOD_CONTEXT_MISSING
DENY_SOD_DYNAMIC_CONFLICT
DENY_SOD_STATIC_CONFLICT
DENY_SUBJECT_INACTIVE
DENY_SUBJECT_NOT_FOUND
DENY_TENANT_INACTIVE
DENY_TENANT_NOT_FOUND
```

Existing reason-code meanings must not be silently repurposed in 1.x.

A genuinely new denial/allow condition may add a new reason in a minor release,
subject to explicit API review.

## PermissionCode contract

`PermissionCode` is the canonical stable permission identifier.

Accepted form:

```text
segment.segment[.segment...]

segment := lowercase letter followed by lowercase letters, digits or underscore
minimum segments := 2
```

Examples:

```text
invoice.approve
billing.invoice.read
user_profile.update
```

Input is trimmed and canonicalized to lowercase before validation.

The final segment is `action`; all preceding segments compose `resource`.

Rejected examples include:

```text
read
.read
invoice.
invoice-read
invoice..read
```

Permission names should describe a durable business capability, not an HTTP route,
UI button or framework-specific operation.

## Change policy

Changing the meaning of an existing permission/reason/error code is breaking even
if the Python type/signature is unchanged.

For 1.x, prefer adding a new explicit code over reusing an existing code with a new
meaning.
