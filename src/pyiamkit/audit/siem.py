"""Vendor-neutral security event export contracts."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Protocol

from .outbox import OutboxEvent
from .security import SecurityEvent, SecuritySeverity

SECURITY_EVENT_OUTBOX_KIND = "pyiamkit.security_event.v1"
SECURITY_EVENT_AGGREGATE_TYPE = "SecurityEvent"


@dataclass(frozen=True, slots=True)
class SecurityEventEnvelope:
    """Portable SIEM envelope independent from any vendor or transport."""

    event_id: str
    event_type: str
    severity: SecuritySeverity
    occurred_at: datetime
    tenant_id: str | None = None
    actor_id: str | None = None
    subject_id: str | None = None
    correlation_id: str | None = None
    payload: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        event_id = self.event_id.strip()
        event_type = self.event_type.strip()
        if not event_id:
            raise ValueError("SecurityEventEnvelope.event_id must not be empty")
        if not event_type:
            raise ValueError("SecurityEventEnvelope.event_type must not be empty")
        if not isinstance(self.severity, SecuritySeverity):
            raise TypeError("SecurityEventEnvelope.severity must be a SecuritySeverity")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("SecurityEventEnvelope.occurred_at must be UTC-aware")

        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "tenant_id", self._optional_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "actor_id", self._optional_text(self.actor_id, "actor_id"))
        object.__setattr__(self, "subject_id", self._optional_text(self.subject_id, "subject_id"))
        object.__setattr__(
            self,
            "correlation_id",
            self._optional_text(self.correlation_id, "correlation_id"),
        )
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    @classmethod
    def from_security_event(cls, event: SecurityEvent) -> "SecurityEventEnvelope":
        """Project one domain SecurityEvent into the portable export envelope."""

        return cls(
            event_id=str(event.id),
            event_type=event.event_type,
            severity=event.severity,
            occurred_at=event.occurred_at,
            tenant_id=event.tenant_id,
            actor_id=event.actor_id,
            subject_id=event.subject_id,
            correlation_id=event.correlation_id,
            payload=event.payload,
        )

    @classmethod
    def from_outbox_event(cls, event: OutboxEvent) -> "SecurityEventEnvelope":
        """Decode the canonical SecurityEvent outbox representation."""

        if event.aggregate_type != SECURITY_EVENT_AGGREGATE_TYPE:
            raise ValueError("Outbox event is not a SecurityEvent publication intent")
        if event.event_version != 1:
            raise ValueError("Unsupported SecurityEvent outbox version")
        if event.aggregate_id is None:
            raise ValueError("SecurityEvent outbox event requires aggregate_id")

        payload = event.payload
        if payload.get("kind") != SECURITY_EVENT_OUTBOX_KIND:
            raise ValueError("Outbox event does not use the SecurityEvent envelope contract")

        event_id = cls._required_string(payload, "event_id")
        if event_id != event.aggregate_id:
            raise ValueError("SecurityEvent outbox event_id must match aggregate_id")

        severity_value = cls._required_string(payload, "severity")
        try:
            severity = SecuritySeverity(severity_value)
        except ValueError as exc:
            raise ValueError("SecurityEvent outbox severity is invalid") from exc

        security_payload = payload.get("payload")
        if not isinstance(security_payload, Mapping):
            raise ValueError("SecurityEvent outbox payload must be a mapping")

        return cls(
            event_id=event_id,
            event_type=event.event_type,
            severity=severity,
            occurred_at=event.occurred_at,
            tenant_id=event.tenant_id,
            actor_id=cls._optional_payload_string(payload, "actor_id"),
            subject_id=cls._optional_payload_string(payload, "subject_id"),
            correlation_id=cls._optional_payload_string(payload, "correlation_id"),
            payload=security_payload,
        )

    @staticmethod
    def _optional_text(value: str | None, field_name: str) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError(
                f"SecurityEventEnvelope.{field_name} must not be empty when provided"
            )
        return normalized

    @staticmethod
    def _required_string(payload: Mapping[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"SecurityEvent outbox {key} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _optional_payload_string(payload: Mapping[str, object], key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"SecurityEvent outbox {key} must be a non-empty string when provided")
        return value.strip()


class SecurityEventSink(Protocol):
    """Vendor-neutral destination for canonical security event envelopes."""

    def emit(self, event: SecurityEventEnvelope) -> None: ...


class GenericSecurityEventExporter:
    """Outbox EventPublisher adapter that forwards SecurityEvents to a SIEM sink."""

    def __init__(self, sink: SecurityEventSink) -> None:
        self._sink = sink

    def publish(self, event: OutboxEvent) -> None:
        self._sink.emit(SecurityEventEnvelope.from_outbox_event(event))


def security_event_to_outbox(event: SecurityEvent) -> OutboxEvent:
    """Create the canonical durable publication intent for one SecurityEvent."""

    return OutboxEvent(
        event_type=event.event_type,
        event_version=1,
        aggregate_type=SECURITY_EVENT_AGGREGATE_TYPE,
        aggregate_id=str(event.id),
        tenant_id=event.tenant_id,
        occurred_at=event.occurred_at,
        payload={
            "kind": SECURITY_EVENT_OUTBOX_KIND,
            "event_id": str(event.id),
            "severity": event.severity.value,
            "actor_id": event.actor_id,
            "subject_id": event.subject_id,
            "correlation_id": event.correlation_id,
            "payload": dict(event.payload),
        },
    )
