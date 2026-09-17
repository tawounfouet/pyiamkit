from datetime import UTC, datetime

from pyiamkit.audit import AuditCategory, AuditEvent, AuditOutcome, DomainEventAuditBridge
from pyiamkit.audit.adapters import InMemoryAuditRepository
from pyiamkit.shared import DomainEvent

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_in_memory_audit_repository_is_append_only_and_queryable() -> None:
    repository = InMemoryAuditRepository()
    event = AuditEvent(
        category=AuditCategory.AUTHORIZATION,
        event_type="AuthorizationDecision",
        occurred_at=NOW,
        subject_id="subject-1",
        outcome=AuditOutcome.ALLOW,
        correlation_id="corr-1",
    )
    repository.append(event)

    assert repository.all() == (event,)
    assert repository.by_subject("subject-1") == (event,)
    assert repository.by_correlation_id("corr-1") == (event,)


def test_domain_event_bridge_records_domain_events() -> None:
    repository = InMemoryAuditRepository()
    bridge = DomainEventAuditBridge(repository)
    bridge.publish(
        (
            DomainEvent(
                event_type="RoleAssigned",
                occurred_at=NOW,
                metadata={"role_id": "role-1"},
            ),
        )
    )

    event = repository.all()[0]
    assert event.category is AuditCategory.DOMAIN
    assert event.event_type == "RoleAssigned"
    assert event.metadata["role_id"] == "role-1"
