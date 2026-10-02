"""SQLAlchemy transactional outbox persistence."""

from sqlalchemy import insert, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pyiamkit.audit import (
    AuditEvent,
    OutboxEvent,
    OutboxEventId,
    OutboxStatus,
)

from .audit import _audit_values
from .common import mapping_from_json, optional_utc_from_db, utc_from_db, uuid_from_db
from .schema import audit_event_table, outbox_event_table
from .common import ensure_json_mapping


class SqlAlchemyOutboxRepository:
    """Append-only OutboxRepository backed by the caller-owned Session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: OutboxEvent) -> None:
        try:
            with self._session.begin_nested():
                self._session.execute(
                    insert(outbox_event_table).values(**_outbox_values(event))
                )
        except IntegrityError as exc:
            raise ValueError(f"Outbox event {event.id} already exists") from exc

    def get(self, event_id: OutboxEventId) -> OutboxEvent | None:
        row = (
            self._session.execute(
                select(outbox_event_table).where(outbox_event_table.c.id == event_id.value)
            )
            .mappings()
            .first()
        )
        return None if row is None else _outbox_from_row(row)

    def pending(self, *, limit: int = 100) -> tuple[OutboxEvent, ...]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be an integer >= 1")
        rows = (
            self._session.execute(
                select(outbox_event_table)
                .where(outbox_event_table.c.status == OutboxStatus.PENDING.value)
                .order_by(outbox_event_table.c.occurred_at, outbox_event_table.c.id)
                .limit(limit)
            )
            .mappings()
            .all()
        )
        return tuple(_outbox_from_row(row) for row in rows)


class SqlAlchemyAuditOutboxWriter:
    """Atomically append audit evidence and publication intent in one Session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, audit_event: AuditEvent, outbox_event: OutboxEvent) -> None:
        try:
            with self._session.begin_nested():
                self._session.execute(
                    insert(audit_event_table).values(**_audit_values(audit_event))
                )
                self._session.execute(
                    insert(outbox_event_table).values(**_outbox_values(outbox_event))
                )
        except IntegrityError as exc:
            raise ValueError("Audit/outbox pair conflicts with existing records") from exc


def _outbox_values(event: OutboxEvent) -> dict[str, object]:
    return {
        "id": event.id.value,
        "event_type": event.event_type,
        "event_version": event.event_version,
        "aggregate_type": event.aggregate_type,
        "aggregate_id": event.aggregate_id,
        "aggregate_version": event.aggregate_version,
        "tenant_id": event.tenant_id,
        "payload_json": ensure_json_mapping(event.payload),
        "occurred_at": event.occurred_at,
        "published_at": event.published_at,
        "attempts": event.attempts,
        "status": event.status.value,
    }


def _outbox_from_row(row: RowMapping) -> OutboxEvent:
    aggregate_version = row["aggregate_version"]
    return OutboxEvent(
        id=OutboxEventId(uuid_from_db(row["id"])),
        event_type=str(row["event_type"]),
        event_version=int(row["event_version"]),
        aggregate_type=(
            None if row["aggregate_type"] is None else str(row["aggregate_type"])
        ),
        aggregate_id=None if row["aggregate_id"] is None else str(row["aggregate_id"]),
        aggregate_version=(
            None if aggregate_version is None else int(aggregate_version)
        ),
        tenant_id=None if row["tenant_id"] is None else str(row["tenant_id"]),
        payload=mapping_from_json(row["payload_json"]),
        occurred_at=utc_from_db(row["occurred_at"]),
        published_at=optional_utc_from_db(row["published_at"]),
        attempts=int(row["attempts"]),
        status=OutboxStatus(str(row["status"])),
    )
