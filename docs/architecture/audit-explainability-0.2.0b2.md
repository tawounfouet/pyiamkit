# Audit & Decision Explainability — 0.2.0b2

`0.2.0b2` introduces a dedicated append-only audit context and safe explanation projections for runtime authorization decisions.

## Decision identity

Every `AuthorizationDecision` owns an opaque `AuthorizationDecisionId`. The identifier links the runtime decision to its audit projection without making correlation IDs globally unique.

## Explanation levels

### SUMMARY

Designed for ordinary application surfaces. It exposes:

- allowed / denied;
- structured `reason_code`;
- a short non-sensitive summary.

It deliberately omits the internal RoleBinding/Role/rule path.

### DETAILED

Designed for trusted administration, diagnostics and audit investigations. It additionally exposes the existing `explanation_path` containing the internal decision provenance.

```python
summary = decision.explanation()
detailed = decision.explanation(ExplanationLevel.DETAILED)
```

The original `AuthorizationEngine.explain()` contract remains unchanged. `AuthorizationEngine.describe()` returns a `DecisionExplanation` directly.

## Audit context

```text
AuthorizationDecision
        ↓
AuthorizationDecisionAuditRecorder
        ↓
AuditSink
        ↓
append-only store / SIEM / stream
```

The `pyiamkit.audit` bounded context contains:

- `AuditEvent`;
- `AuditEventId`;
- `AuditCategory`;
- `AuditOutcome`;
- `AuditSink`;
- `AuditRepository`;
- `DomainEventAuditBridge`;
- `InMemoryAuditRepository` reference adapter.

## Data minimization

Authorization audit projection includes only the resource type and identifier. `ResourceDescriptor.attributes` are never copied into an authorization audit event.

This avoids leaking arbitrary business payloads, secrets or regulated data through the authorization layer.

## Failure semantics

When no `AuditSink` is configured, authorization behavior remains unchanged.

When an `AuditSink` is configured, recording occurs synchronously during decision finalization. Sink failures are propagated rather than silently ignored, allowing the host application to fail closed when audit durability is mandatory.

## Domain-event bridge

`DomainEventAuditBridge` implements the shared `DomainEventSink` contract and can be injected into application services to project domain lifecycle events into the same append-only audit stream.

This provides a common path for both:

```text
IAM administrative events
+
runtime authorization decisions
→ Audit context
```
