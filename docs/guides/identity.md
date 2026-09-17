# Identity domain

The `0.1.0a1` Identity domain introduces the first real PyIAMKit aggregate.

## Lifecycle

```text
PENDING -> ACTIVE -> SUSPENDED -> ACTIVE
                   \-> DISABLED -> ARCHIVED
ACTIVE ----------------^ 
```

Valid transitions are explicit and invalid transitions raise `InvalidIdentityTransition`.

## Example

```python
from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.shared import SystemClock

service = IdentityApplicationService(
    repository=InMemoryIdentityRepository(),
    clock=SystemClock(),
    event_sink=InMemoryDomainEventSink(),
)

identity = service.create_user(display_name="Alice")
identity = service.activate_identity(identity.id)
```

The domain does not yet provide passwords, sessions, roles, tenants or authorization. Those capabilities are introduced by later milestones.
