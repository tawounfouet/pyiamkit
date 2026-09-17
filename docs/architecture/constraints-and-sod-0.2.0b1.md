# Constraints & Separation of Duties — 0.2.0b1

`0.2.0b1` adds restrictive business governance on top of scoped hierarchical RBAC.

## Core principle

Governance rules never create an authorization grant:

```text
RBAC / hierarchy proves candidate ALLOW
              ↓
Static SoD
              ↓
Dynamic SoD
              ↓
Resource constraints
              ↓
ALLOW or restrictive DENY
```

## Resource context

`ResourceDescriptor` is framework-neutral and carries the protected resource identifier, tenant and attributes required by runtime rules.

## Constraints

The first built-in constraints are:

- `NumericMaximumConstraint` — e.g. `payment.amount <= 100000`;
- `ResourceAttributeEqualsConstraint` — e.g. `invoice.status == pending`.

If a rule applies but required context is missing or malformed, evaluation fails closed.

## Separation of Duties

### Static SoD

`MutuallyExclusiveRolesRule` prevents a subject from simultaneously holding two conflicting effective Roles. Effective Roles include inherited parents, preventing hierarchy-based SoD bypass.

Example:

```text
PaymentPreparer  X  PaymentApprover
```

Static SoD is checked before a new RoleBinding is persisted.

### Dynamic SoD

`DistinctActorSoDRule` compares the current subject with an actor attribute on the resource.

Example:

```text
permission = payment.approve
resource.prepared_by != current subject
```

This allows a user to be eligible for approval while still preventing self-approval of a transaction they prepared.

## Decision provenance

Governance denials expose a `matched_rule_id` and a structured reason code. The explanation path references the binding, Role and governance rule responsible for the restrictive decision.
