"""Create and activate a User Identity using only in-memory adapters."""

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.shared import SystemClock

repository = InMemoryIdentityRepository()
events = InMemoryDomainEventSink()
service = IdentityApplicationService(
    repository=repository,
    clock=SystemClock(),
    event_sink=events,
)

alice = service.create_user(
    display_name="Alice",
    primary_email="alice@example.com",
)
alice = service.activate_identity(alice.id)

print(alice.id, alice.status.value)
print([event.event_type for event in events.events])
