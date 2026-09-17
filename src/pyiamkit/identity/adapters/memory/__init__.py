"""In-memory Identity adapters."""

from .event_sink import InMemoryDomainEventSink
from .repository import InMemoryIdentityRepository

__all__ = ["InMemoryDomainEventSink", "InMemoryIdentityRepository"]
