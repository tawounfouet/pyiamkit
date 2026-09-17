"""Identity event publication port."""

from collections.abc import Sequence
from typing import Protocol

from pyiamkit.shared import DomainEvent


class DomainEventSink(Protocol):
    def publish(self, events: Sequence[DomainEvent]) -> None: ...
