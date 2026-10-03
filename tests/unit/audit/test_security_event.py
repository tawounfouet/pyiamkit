from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType

import pytest

from pyiamkit.audit import (
    AuditCategory,
    SecurityEvent,
    SecurityEventId,
    SecuritySeverity,
)

NOW = datetime(2026, 10, 2, 14, 15, tzinfo=UTC)


def test_security_event_is_immutable_and_normalizes_context() -> None:
    event = SecurityEvent(
        event_type="  IdentityDisabled  ",
        severity=SecuritySeverity.HIGH,
        occurred_at=NOW,
        tenant_id=" tenant-1 ",
        actor_id=" admin-1 ",
        subject_id=" user-1 ",
        correlation_id=" corr-1 ",
        payload={"reason": "policy"},
    )

    assert isinstance(event.id, SecurityEventId)
    assert event.event_type == "IdentityDisabled"
    assert event.tenant_id == "tenant-1"
    assert event.actor_id == "admin-1"
    assert event.subject_id == "user-1"
    assert event.correlation_id == "corr-1"
    assert event.payload == {"reason": "policy"}
    assert isinstance(event.payload, MappingProxyType)

    with pytest.raises(TypeError):
        event.payload["reason"] = "tampered"  # type: ignore[index]


def test_security_event_copies_payload_before_freezing() -> None:
    payload: dict[str, object] = {"ip": "203.0.113.1"}
    event = SecurityEvent(
        event_type="AuthenticationFailed",
        severity=SecuritySeverity.MEDIUM,
        occurred_at=NOW,
        payload=payload,
    )

    payload["ip"] = "198.51.100.2"

    assert event.payload == {"ip": "203.0.113.1"}


@pytest.mark.parametrize(
    "severity",
    [
        SecuritySeverity.INFO,
        SecuritySeverity.LOW,
        SecuritySeverity.MEDIUM,
        SecuritySeverity.HIGH,
        SecuritySeverity.CRITICAL,
    ],
)
def test_security_event_supports_portable_severity_levels(
    severity: SecuritySeverity,
) -> None:
    event = SecurityEvent(
        event_type="SecuritySignal",
        severity=severity,
        occurred_at=NOW,
    )

    assert event.severity is severity


@pytest.mark.parametrize(
    ("field_name", "kwargs"),
    [
        ("event_type", {"event_type": "  "}),
        ("tenant_id", {"tenant_id": "  "}),
        ("actor_id", {"actor_id": "  "}),
        ("subject_id", {"subject_id": "  "}),
        ("correlation_id", {"correlation_id": "  "}),
    ],
)
def test_security_event_rejects_empty_text_fields(
    field_name: str,
    kwargs: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "event_type": "SecuritySignal",
        "severity": SecuritySeverity.INFO,
        "occurred_at": NOW,
    }
    values.update(kwargs)

    with pytest.raises(ValueError, match=field_name):
        SecurityEvent(**values)  # type: ignore[arg-type]


def test_security_event_requires_strict_utc_timestamp() -> None:
    with pytest.raises(ValueError, match="UTC-aware"):
        SecurityEvent(
            event_type="SecuritySignal",
            severity=SecuritySeverity.INFO,
            occurred_at=NOW.replace(tzinfo=None),
        )

    with pytest.raises(ValueError, match="UTC-aware"):
        SecurityEvent(
            event_type="SecuritySignal",
            severity=SecuritySeverity.INFO,
            occurred_at=NOW.astimezone(timezone(timedelta(hours=1))),
        )


def test_audit_category_exposes_security_stream() -> None:
    assert AuditCategory.SECURITY.value == "security"
