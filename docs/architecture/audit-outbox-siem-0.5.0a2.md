# Audit / Outbox / SIEM — 0.5.0a2

## Status

This document records the vendor-neutral SIEM export contract introduced during the
PyIAMKit `0.5.0a2` Audit / Outbox / SIEM milestone.

Implemented lots:

- LOT-B1-01 — Security Event Foundations
- LOT-B1-02 — Transactional Audit + Outbox Foundations
- LOT-B1-03 — Outbox Publisher + Delivery State
- LOT-B1-04 — SIEM Port + Generic Exporter
- LOT-B1-05 — Reliability Closure

## Architecture

```text
SecurityEvent
     │
     │ security_event_to_outbox()
     ▼
OutboxEvent
     │
     │ business transaction commits
     ▼
OutboxPublisher
     │
     ▼
GenericSecurityEventExporter
     │
     ▼
SecurityEventSink
     │
     ├── Splunk adapter
     ├── Microsoft Sentinel adapter
     ├── Elastic adapter
     ├── Datadog adapter
     ├── Generic HTTP adapter
     └── Syslog adapter
```

No vendor SDK or transport dependency is part of the core contract.

## SecurityEventEnvelope

The portable export envelope contains:

```text
event_id
event_type
severity
tenant_id
actor_id
subject_id
occurred_at
correlation_id
payload
```

The envelope is immutable at the top level and uses UTC-aware timestamps.

## Canonical outbox representation

A `SecurityEvent` becomes an `OutboxEvent` with:

```text
aggregate_type = "SecurityEvent"
aggregate_id   = SecurityEvent.id
event_type     = SecurityEvent.event_type
event_version  = 1
tenant_id      = SecurityEvent.tenant_id
occurred_at    = SecurityEvent.occurred_at
```

Its payload carries the canonical marker:

```text
pyiamkit.security_event.v1
```

plus severity, actor, subject, correlation and the redacted event payload.

The decoder fails closed when the aggregate type, version, marker, event identity,
severity or payload shape is invalid.

## Secret redaction

Security event export must not become a raw-secret exfiltration path.

Before durable outbox creation or direct envelope projection, PyIAMKit recursively
redacts values for explicitly sensitive field names such as:

```text
password
secret
raw_secret
token
raw_token
access_token
refresh_token
client_secret
api_key
private_key
authorization
credential
```

Opaque references such as `secret_reference` are intentionally preserved because
they point to protected external material rather than containing the raw secret.

Applications remain responsible for not hiding raw credentials under misleading,
non-sensitive field names.

## Delivery semantics

SIEM delivery uses the existing outbox delivery state machine:

```text
PENDING
   │
   ├── sink success ──────> PUBLISHED
   │                        attempts + 1
   │                        published_at set
   │
   └── sink failure ──────> FAILED
                            attempts + 1
                            retryable
```

A SIEM outage occurs after the business transaction has committed. It therefore does
not roll back the business mutation, audit evidence or durable outbox intent.

Delivery remains at-least-once. If the external sink accepts an event but persistence
of the published state fails, the event may be emitted again. Downstream consumers
must use `event_id` for idempotency/deduplication.

## Trust boundary

`SecurityEventSink` is an outbound integration port only. A SIEM adapter:

- cannot grant Roles or Permissions;
- cannot create RoleBindings;
- cannot modify Tenant membership;
- cannot alter authorization decisions;
- is not an IAM source of truth.

A sink failure affects observability/export availability, not authorization authority.

## Reliability closure

The milestone explicitly qualifies the failure boundaries required by M18:

- business write + audit + outbox commit atomically;
- caller rollback removes business write + audit + outbox together;
- an outbox conflict rolls back the paired audit insert;
- an audit persistence conflict prevents the paired outbox intent from being written;
- a worker cannot observe an uncommitted outbox intent;
- sink publication failure leaves a durable retryable event;
- retry can transition FAILED to PUBLISHED;
- a successful external delivery followed by delivery-state persistence failure may be
  published again, preserving at-least-once semantics;
- duplicate delivery carries the same canonical `event_id`;
- an idempotent downstream consumer can suppress duplicate side effects by
  remembering `event_id`.

Consumer idempotency is deliberately a downstream responsibility. PyIAMKit provides
the stable event identity and at-least-once delivery contract; it does not pretend
that exactly-once external delivery exists.

## Qualification

The complete `0.5.0a2` milestone proves:

- canonical SecurityEvent → OutboxEvent → SecurityEventEnvelope round-trip;
- preservation of tenant / actor / subject / correlation context;
- rejection of non-security or tampered outbox messages;
- recursive sensitive-field redaction;
- transactional audit/outbox atomicity in SQLite and PostgreSQL;
- post-commit outbox visibility in PostgreSQL;
- successful sink delivery marks the outbox event published;
- sink failure marks delivery failed and retryable;
- retry succeeds without losing the original durable intent;
- duplicate publish remains compatible with `event_id`-based consumer idempotency;
- audit persistence failure cannot leak an outbox publication intent;
- no vendor dependency is introduced into the core package.
