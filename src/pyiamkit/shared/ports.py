"""Cross-cutting application ports shared by bounded contexts."""

from collections.abc import Sequence
from typing import Protocol

from .events import DomainEvent


class DomainEventSink(Protocol):
    """Publishes domain events without coupling the domain to a transport."""

    def publish(self, events: Sequence[DomainEvent]) -> None: ...
