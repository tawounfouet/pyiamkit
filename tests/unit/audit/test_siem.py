from datetime import UTC, datetime
from types import MappingProxyType

import pytest

from pyiamkit.audit import (
    GenericSecurityEventExporter,
    OutboxEvent,
    OutboxPublisher,
    OutboxStatus,
    SecurityEvent,
    SecurityEventEnvelope,
    SecuritySeverity,
    security_event_to_outbox,
)
from pyiamkit.audit.adapters import InMemoryOutboxRepository
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 3, 7, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


class RecordingSecurityEventSink:
    def __init__(self, *, failures: int = 0) -> None:
        self.events: list[SecurityEventEnvelope] = []
        self._failures = failures

    def emit(self, event: SecurityEventEnvelope) -> None:
        if self._failures > 0:
            self._failures -= 1
            raise RuntimeError("SIEM unavailable")
        self.events.append(event)


def _security_event() -> SecurityEvent:
    return SecurityEvent(
        event_type="SoDViolationDetected",
        severity=SecuritySeverity.HIGH,
        occurred_at=NOW,
        tenant_id="tenant-1",
        actor_id="actor-1",
        subject_id="subject-1",
        correlation_id="corr-1",
        payload={"rule_id": "sod-42", "resource": "invoice-7"},
    )


def test_security_event_envelope_projects_domain_event_without_aliasing_payload() -> None:
    event = _security_event()

    envelope = SecurityEventEnvelope.from_security_event(event)

    assert envelope.event_id == str(event.id)
    assert envelope.event_type == "SoDViolationDetected"
    assert envelope.severity is SecuritySeverity.HIGH
    assert envelope.tenant_id == "tenant-1"
    assert envelope.actor_id == "actor-1"
    assert envelope.subject_id == "subject-1"
    assert envelope.correlation_id == "corr-1"
    assert envelope.payload == {"rule_id": "sod-42", "resource": "invoice-7"}
    assert isinstance(envelope.payload, MappingProxyType)

    with pytest.raises(TypeError):
        envelope.payload["rule_id"] = "changed"  # type: ignore[index]


def test_security_event_outbox_round_trip_preserves_canonical_envelope() -> None:
    event = _security_event()

    outbox = security_event_to_outbox(event)
    envelope = SecurityEventEnvelope.from_outbox_event(outbox)

    assert outbox.aggregate_type == "SecurityEvent"
    assert outbox.aggregate_id == str(event.id)
    assert outbox.event_type == event.event_type
    assert outbox.tenant_id == event.tenant_id
    assert envelope == SecurityEventEnvelope.from_security_event(event)


def test_security_event_exporter_forwards_canonical_outbox_event() -> None:
    sink = RecordingSecurityEventSink()
    exporter = GenericSecurityEventExporter(sink)
    event = _security_event()

    exporter.publish(security_event_to_outbox(event))

    assert sink.events == [SecurityEventEnvelope.from_security_event(event)]


def test_security_event_exporter_rejects_non_security_outbox_event() -> None:
    sink = RecordingSecurityEventSink()
    exporter = GenericSecurityEventExporter(sink)
    outbox = OutboxEvent(
        event_type="IdentityCreated",
        occurred_at=NOW,
        payload={"identity_id": "identity-1"},
    )

    with pytest.raises(ValueError, match="not a SecurityEvent"):
        exporter.publish(outbox)

    assert sink.events == []


def test_security_event_exporter_rejects_tampered_event_identity() -> None:
    event = _security_event()
    canonical = security_event_to_outbox(event)
    tampered = OutboxEvent(
        event_type=canonical.event_type,
        event_version=canonical.event_version,
        aggregate_type=canonical.aggregate_type,
        aggregate_id="different-security-event-id",
        tenant_id=canonical.tenant_id,
        occurred_at=canonical.occurred_at,
        payload=canonical.payload,
    )

    with pytest.raises(ValueError, match="must match aggregate_id"):
        SecurityEventEnvelope.from_outbox_event(tampered)


def test_siem_failure_is_retryable_through_outbox_publisher() -> None:
    repository = InMemoryOutboxRepository()
    event = _security_event()
    outbox = security_event_to_outbox(event)
    repository.append(outbox)
    sink = RecordingSecurityEventSink(failures=1)
    service = OutboxPublisher(
        repository=repository,
        publisher=GenericSecurityEventExporter(sink),
        clock=FrozenClock(),
    )

    first = service.publish_batch()

    failed = repository.get(outbox.id)
    assert failed is not None
    assert failed.status is OutboxStatus.FAILED
    assert failed.attempts == 1
    assert failed.published_at is None
    assert sink.events == []
    assert first.failed == 1

    second = service.publish_batch()

    published = repository.get(outbox.id)
    assert published is not None
    assert published.status is OutboxStatus.PUBLISHED
    assert published.attempts == 2
    assert published.published_at == NOW
    assert sink.events == [SecurityEventEnvelope.from_security_event(event)]
    assert second.published == 1


def test_security_event_export_redacts_sensitive_payload_fields_recursively() -> None:
    event = SecurityEvent(
        event_type="AuthenticationFailed",
        severity=SecuritySeverity.MEDIUM,
        occurred_at=NOW,
        payload={
            "password": "raw-password",
            "secret_reference": "vault://iam/alice",
            "nested": {
                "access-token": "raw-access-token",
                "reason": "invalid_credentials",
            },
        },
    )

    envelope = SecurityEventEnvelope.from_security_event(event)
    outbox = security_event_to_outbox(event)
    round_trip = SecurityEventEnvelope.from_outbox_event(outbox)

    assert envelope.payload["password"] == "[REDACTED]"
    assert envelope.payload["secret_reference"] == "vault://iam/alice"
    nested = envelope.payload["nested"]
    assert isinstance(nested, dict)
    assert nested["access-token"] == "[REDACTED]"
    assert nested["reason"] == "invalid_credentials"
    assert round_trip == envelope
    assert "raw-password" not in repr(outbox.payload)
    assert "raw-access-token" not in repr(outbox.payload)
