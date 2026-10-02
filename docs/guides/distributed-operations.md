# Distributed operations

PyIAMKit `0.5.0a1` adds a distributed operational layer around the existing
authoritative IAM and authorization model.

The design deliberately separates durable truth from performance infrastructure:

```text
AuthorizationEngine             semantic authorization authority
PostgreSQL / repositories       durable IAM and SecurityState authority
SecurityStateStamp              cache-validity proof
AuthorizationCache              derived acceleration
RevocationRegistry              deny-fast overlay
InvalidationEvent / Pub/Sub     low-latency signal
Redis                           optional operational projection
```

Redis is never sufficient to justify an `ALLOW`.

## Installation

The in-memory reference adapters are part of the core package.

Redis-backed adapters are optional:

```bash
python -m pip install "pyiamkit[redis]"
```

SQLAlchemy-backed authoritative security state is available with:

```bash
python -m pip install "pyiamkit[sqlalchemy]"
```

For PostgreSQL:

```bash
python -m pip install "pyiamkit[postgres]"
```

## SecurityState

A cache entry is valid only when its recorded `SecurityStateStamp` exactly
matches the current authoritative stamp.

The stamp has nine dimensions:

```text
runtime_generation
identity
tenant
membership
subject_authorization
tenant_authorization
global_authorization
governance
authentication
```

The dimensions intentionally have different scopes:

- `identity` and `authentication` are Identity-scoped;
- `tenant`, `tenant_authorization` and `governance` are Tenant-scoped;
- `membership` and `subject_authorization` are scoped to an Identity/Tenant pair;
- `runtime_generation` and `global_authorization` are global.

Use `SecurityStateReader` and `SecurityStateWriter` as the application boundary.
Reference implementations are:

```python
from pyiamkit.operations.adapters import InMemorySecurityStateStore
from pyiamkit.persistence.sqlalchemy import SqlAlchemySecurityStateStore
```

`SqlAlchemySecurityStateStore` uses the caller-owned transaction. A bump is
therefore rolled back with the surrounding transaction when that transaction is
rolled back.

## DistributedAuthorizationRuntime

`DistributedAuthorizationRuntime` wraps the existing `AuthorizationEngine`:

```text
request
  ↓
revocation checks
  ↓
exact-stamp cache lookup
  ↓
authoritative AuthorizationEngine when needed
  ↓
state re-read
  ↓
post-evaluation revocation checks
  ↓
cache ALLOW only when state remained stable
```

A cached decision is never returned solely because the cache contains a value.
The runtime verifies the current authoritative stamp and checks relevant
revocation markers.

If security state changes during evaluation, the runtime retries a bounded
number of times. If state does not stabilize, it raises
`AuthorizationRuntimeUnavailable` rather than returning a potentially stale
`ALLOW`.

DENY caching is disabled by default.

## Mutation hooks

`SecurityStateMutationEventSink` decorates an existing `DomainEventSink` and
translates security-sensitive domain events into authoritative state-version
bumps.

Typical mappings include:

```text
Identity lifecycle           → identity
Tenant lifecycle             → tenant
Membership lifecycle         → membership
RoleBinding lifecycle        → subject_authorization
tenant Role mutation         → tenant_authorization
global Role / Permission     → global_authorization
tenant governance            → governance
global governance            → runtime_generation
Credential / Session / MFA   → authentication
```

Negative lifecycle events may also emit version-aware deny-fast markers for
Identity, Tenant, Membership and RoleBinding targets.

`SessionRevoked` emits a terminal Session marker whose expiry is bounded by
the Session expiry.

The mutation hook does not eagerly publish a full Redis state projection. The
authoritative state remains transaction-bound; projection is warmed after an
authoritative read through `ProjectingSecurityStateReader`.

## Redis authorization cache

The optional adapter is imported explicitly:

```python
from pyiamkit.operations.adapters.redis import RedisAuthorizationCache
```

It uses:

- canonical versioned JSON payloads;
- opaque SHA-256 key material;
- absolute Redis expiry;
- exact `SecurityStateStamp` validation;
- best-effort deletion of stale or corrupt entries;
- `SCAN`, never `KEYS`, for namespace clearing.

Redis connection errors become cache misses/no-ops. They never become an
authorization grant.

## Redis revocation registry

The optional adapter is:

```python
from pyiamkit.operations.adapters.redis import RedisRevocationRegistry
```

The registry stores one marker per target and performs atomic monotonic
replacement.

For reactivable objects, ordering uses `source_version`. For terminal Session
markers, ordering uses `revoked_at`.

Duplicate replay is idempotent, older markers cannot overwrite newer markers,
and conflicting payloads at the same revision are rejected.

A registry read failure is not interpreted as “not revoked”. The distributed
authorization runtime bypasses cached ALLOW decisions when revocation state is
uncertain and evaluates authoritatively instead.

## Redis state projection

`RedisSecurityStateProjection` is explicitly non-authoritative:

```python
from pyiamkit.operations import ProjectingSecurityStateReader
from pyiamkit.operations.adapters.redis import RedisSecurityStateProjection
```

`ProjectingSecurityStateReader` always reads the authoritative
`SecurityStateReader` first and only then warms the projection best-effort.

The Redis projection refuses a stamp that regresses any state dimension.

## Invalidation Pub/Sub

The generic contracts are:

```python
from pyiamkit.operations import (
    AuthorizationCacheInvalidationHandler,
    InvalidationEvent,
    InvalidationHandler,
    InvalidationPublisher,
)
```

Redis provides:

```python
from pyiamkit.operations.adapters.redis import (
    RedisInvalidationPublisher,
    RedisInvalidationSubscriber,
)
```

The subscriber rejects corrupt payloads, duplicate `event_id` values and
stale/equal versions for the same semantic stream.

Pub/Sub remains an optimization. Losing an invalidation message can leave a
local cache entry present, but the next lookup still compares its stamp with
authoritative state and therefore cannot trust a stale `ALLOW`.

## JWT Session revocation overlay

`JwtTokenProvider` accepts an optional `revocation_registry`:

```python
tokens = JwtTokenProvider(
    ...,
    session_repository=sessions,
    revocation_registry=revocations,
)
```

Verification order is:

```text
signature / issuer / audience / time
        ↓
SESSION revocation overlay
        ↓
authoritative SessionRepository validation
```

A revocation hit rejects before the Session repository lookup.

A registry miss still checks the Session repository.

If the registry is unavailable, verification falls back to the authoritative
Session repository instead of accepting the token from the Redis result alone.

## Failure model

The distributed layer is designed so that infrastructure degradation reduces
optimization before it reduces correctness:

```text
cache unavailable            → authoritative evaluation
cache payload corrupt        → MISS + best-effort eviction
revocation uncertain         → bypass cached ALLOW
Pub/Sub message lost         → stamp mismatch still invalidates stale cache
Pub/Sub message duplicated   → deduplicated
Pub/Sub message reordered    → stale/equal signal rejected
state never stabilizes       → AuthorizationRuntimeUnavailable
```

The central invariant is:

> Distributed operational state may accelerate a correct decision, but it may
> not manufacture a trusted stale ALLOW.

## Executable examples

See:

```text
examples/distributed_authorization.py
examples/jwt_revocation_overlay.py
```

The Redis adapters are intentionally documented separately from those examples.
The `0.5.0a1` release line is qualified in CI against a real Redis 7 service
using the built and installed wheel.
