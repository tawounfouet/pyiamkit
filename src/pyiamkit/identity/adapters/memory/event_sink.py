"""In-memory event sink used by tests and examples."""

from collections.abc import Sequence

from pyiamkit.shared import DomainEvent


class InMemoryDomainEventSink:
    def __init__(self) -> None:
        self._events: list[DomainEvent] = []

    @property
    def events(self) -> tuple[DomainEvent, ...]:
        return tuple(self._events)

    def publish(self, events: Sequence[DomainEvent]) -> None:
        self._events.extend(events)
