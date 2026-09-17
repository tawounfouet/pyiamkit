from datetime import UTC, datetime

import pytest

from pyiamkit.shared import DomainEvent


def test_domain_event_is_timezone_aware_and_copies_metadata() -> None:
    metadata = {"source": "test"}
    event = DomainEvent(
        event_type="ExampleCreated",
        occurred_at=datetime.now(UTC),
        metadata=metadata,
    )
    metadata["source"] = "changed"

    assert event.metadata["source"] == "test"


def test_domain_event_rejects_empty_type() -> None:
    with pytest.raises(ValueError, match="event_type"):
        DomainEvent(event_type=" ", occurred_at=datetime.now(UTC))


def test_domain_event_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        DomainEvent(event_type="ExampleCreated", occurred_at=datetime.now())
