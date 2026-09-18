"""Authorization-decision audit projection."""

from pyiamkit.audit import AuditCategory, AuditEvent, AuditOutcome, AuditSink

from .domain.decision import AuthorizationDecision


class AuthorizationDecisionAuditRecorder:
    """Project decisions to minimal append-only audit records without resource attributes."""

    def __init__(self, audit_sink: AuditSink) -> None:
        self._audit = audit_sink

    def record(self, decision: AuthorizationDecision) -> AuditEvent:
        resource = decision.resource
        metadata: dict[str, object] = {"decision_id": str(decision.id)}
        if decision.bound_role_id is not None:
            metadata["bound_role_id"] = str(decision.bound_role_id)
        if decision.matched_binding_id is not None:
            metadata["matched_binding_id"] = str(decision.matched_binding_id)
        if decision.matched_role_id is not None:
            metadata["matched_role_id"] = str(decision.matched_role_id)
        if decision.matched_rule_id is not None:
            metadata["matched_rule_id"] = str(decision.matched_rule_id)
        if decision.required_assurance_level is not None:
            metadata["required_assurance_level"] = decision.required_assurance_level.value
        if decision.required_mfa is not None:
            metadata["required_mfa"] = decision.required_mfa

        event = AuditEvent(
            category=AuditCategory.AUTHORIZATION,
            event_type="AuthorizationDecision",
            occurred_at=decision.evaluated_at,
            actor_id=str(decision.subject_id),
            subject_id=str(decision.subject_id),
            tenant_id=str(decision.tenant_id),
            action=str(decision.permission),
            resource_type=None if resource is None else resource.resource_type,
            resource_id=None if resource is None else resource.resource_id,
            outcome=AuditOutcome.ALLOW if decision.allowed else AuditOutcome.DENY,
            reason_code=decision.reason_code.value,
            correlation_id=decision.correlation_id,
            metadata=metadata,
        )
        self._audit.append(event)
        return event
