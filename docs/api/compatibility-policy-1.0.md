# Public Compatibility and Deprecation Policy — 1.x

## Scope

This policy applies to the public contract frozen in PyIAMKit 1.0.0rc1 and promoted
to the 1.x stable line.

The authoritative machine-readable baseline is maintained by the API Compatibility
workflow. `PUBLIC_API.md` remains the human-readable contract index.

## Compatibility promise

Within the 1.x line, PyIAMKit aims to preserve:

- documented import locations;
- public export names;
- required call parameters and compatible defaults;
- public exception classes and stable error codes;
- AuthorizationReason values;
- PermissionCode semantics;
- repository/port method contracts;
- event versioning rules;
- migration compatibility policy.

A patch or minor release must not silently remove or reinterpret one of those
contracts.

## Breaking changes

Examples of breaking changes include:

- removing or renaming a frozen public export;
- changing a required parameter incompatibly;
- removing a public exception or changing its stable code;
- changing/removing an AuthorizationReason;
- changing an existing PermissionCode semantic meaning;
- making a previously valid adapter fail its frozen protocol contract;
- changing persisted structure without a supported migration path;
- changing event meaning/version incompatibly.

Breaking changes normally require the next major version.

## Non-breaking changes

Examples include:

- adding a new opt-in adapter;
- adding a new public API without changing existing contracts;
- adding a new reason/error code for a genuinely new condition;
- performance improvements;
- internal refactors;
- new diagnostics/metrics;
- stricter rejection of behavior that was never part of the documented safe
  contract.

New public API still requires explicit review and an intentional compatibility
baseline update.

## Deprecation lifecycle

The normal lifecycle is:

```text
Active
  ↓
Deprecated
  ↓
Removed in a later major version
```

A public API must not normally jump directly from Active to Removed.

A deprecation must document:

```text
deprecated since
replacement
migration guidance
planned removal major version
```

After 1.0.0, the minimum transition window is normally at least one minor release.
Widely used contracts should receive a longer window when practical.

Python warnings should use `DeprecationWarning` unless another public warning class
is explicitly part of the contract.

## Security exception

A security correction may intentionally change unsafe behavior without waiting for a
major version.

Example: if a cross-Tenant path accidentally allowed access, a patch release may
deny that access immediately.

Such a change must be documented as a security compatibility exception. The project
does not preserve insecure behavior merely for compatibility.

## Experimental/internal API

Importability does not imply stability.

Any future experimental namespace must be explicitly labeled and excluded from the
stable manifest. Private/internal names remain outside compatibility guarantees.

## RC policy

During 1.0.0rc1:

- no new major feature;
- compatibility defects may be fixed;
- naming/error/reason/adapter cleanup is allowed only when deliberately reviewed;
- the baseline is re-generated only for intentional RC contract changes;
- all baseline changes require changelog and public API documentation.

Once 1.0.0 is promoted, the frozen baseline becomes the starting compatibility
contract for the 1.x series.
