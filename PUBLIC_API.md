# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.2.0b1

Adds restrictive authorization-governance contracts from `pyiamkit.authorization`:

```text
AccessGovernanceApplicationService
AuthorizationConstraint
ConstraintEvaluator
ConstraintRepository
DistinctActorSoDRule
DynamicSoDEvaluator
GovernanceRuleId
GovernanceViolation
GovernanceViolationKind
MutuallyExclusiveRolesRule
NumericMaximumConstraint
ResourceAttributeEqualsConstraint
ResourceDescriptor
SeparationOfDutyRule
SoDRuleRepository
StaticSoDEvaluator
StaticSoDViolation
```

`AuthorizationRequest` may now carry a tenant-bound `ResourceDescriptor`, and `AuthorizationDecision` may expose `matched_rule_id` for restrictive governance provenance.

Governance rules in this milestone are deny-only: they are evaluated only after RBAC finds a candidate permission. They can reduce an authorization result to `DENY` but cannot create an `ALLOW`.

Static SoD is also enforced before a conflicting RoleBinding is persisted. Effective inherited Roles participate in that check.

## 0.2.0a2

Adds hierarchical RBAC contracts from `pyiamkit.authorization`:

```text
RoleHierarchyApplicationService
RoleHierarchyResolver
RoleHierarchyError
RoleHierarchyCycle
RoleHierarchyDepthExceeded
RoleHierarchyTenantMismatch
RoleHierarchyUnavailable
```

`Role` exposes `parent_role_ids`, and authorization decisions distinguish:

```text
bound_role_id   # Role referenced by the effective RoleBinding
matched_role_id # Role that actually contributes the matching Permission
```

## 0.2.0a1

Adds the first runtime authorization API from `pyiamkit.authorization`:

```text
AuthorizationDecision
AuthorizationDenied
AuthorizationEngine
AuthorizationReason
AuthorizationRequest
AuthorizationResult
```

Runtime methods:

```text
AuthorizationEngine.authorize()
AuthorizationEngine.can()
AuthorizationEngine.require()
AuthorizationEngine.explain()
```

## 0.1.0b2

Adds scoped role-assignment contracts from `pyiamkit.authorization`:

```text
RoleBinding
RoleBindingId
RoleBindingStatus
GrantSource
RoleBindingApplicationService
RoleBindingRepository
InvalidRoleBinding
InvalidRoleBindingTransition
RoleBindingNotFound
RoleBindingAlreadyExists
RoleNotAssignable
RoleTenantMismatch
```

## 0.1.0b1

Beta Roles and Permissions API is available from `pyiamkit.authorization`.

## 0.1.0a2

Alpha Tenancy API is available from `pyiamkit.tenancy`.

## 0.1.0a1

Alpha Identity API is available from `pyiamkit.identity`.
