# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.3.0a1

Adds optional SQLAlchemy persistence adapters from `pyiamkit.persistence.sqlalchemy`:

```text
SqlAlchemyAuditRepository
SqlAlchemyConstraintRepository
SqlAlchemyIdentityRepository
SqlAlchemyMembershipRepository
SqlAlchemyPermissionCatalogRepository
SqlAlchemyRoleBindingRepository
SqlAlchemyRoleRepository
SqlAlchemySoDRuleRepository
SqlAlchemyTenantRepository
create_schema()
create_session_factory()
create_sqlalchemy_engine()
drop_schema()
```

Installation extras:

```text
pyiamkit[sqlalchemy]  # SQLAlchemy adapter, SQLite-compatible
pyiamkit[postgres]    # SQLAlchemy + psycopg for PostgreSQL
```

The existing domain repository protocols are unchanged. SQLAlchemy adapters receive an existing `Session`, execute persistence operations and deliberately do not commit. Transaction ownership stays with the host application.

`create_schema()` is an alpha bootstrap/test helper, not a substitute for a production migration workflow. PostgreSQL compatibility is qualified in CI against a live PostgreSQL 16 service.

## 0.2.0b2

Adds the append-only audit bounded context from `pyiamkit.audit`:

```text
AuditCategory
AuditEvent
AuditEventId
AuditOutcome
AuditRepository
AuditSink
DomainEventAuditBridge
```

Adds authorization audit and explanation contracts from `pyiamkit.authorization`:

```text
AuthorizationDecisionAuditRecorder
AuthorizationDecisionId
DecisionExplanation
ExplanationLevel
```

`AuthorizationEngine` accepts an optional `audit_sink` and adds:

```text
AuthorizationEngine.describe()
```

The existing `AuthorizationEngine.explain()` contract is preserved. `AuthorizationDecision.explanation()` projects either a safe summary or opt-in detailed internal path.

Authorization audit records deliberately omit resource attribute payloads. A configured audit sink participates synchronously in decision finalization; write failures are not silently ignored.

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

`AuthorizationRequest` may carry a tenant-bound `ResourceDescriptor`, and `AuthorizationDecision` may expose `matched_rule_id` for restrictive governance provenance.

Governance rules are deny-only: they can reduce a candidate RBAC authorization to `DENY` but cannot create an `ALLOW`.

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
