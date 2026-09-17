"""SQLAlchemy append-only audit repository."""

from sqlalchemy import insert, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pyiamkit.audit import AuditCategory, AuditEvent, AuditEventId, AuditOutcome

from .common import ensure_json_mapping, mapping_from_json, utc_from_db, uuid_from_db
from .schema import audit_event_table


class SqlAlchemyAuditRepository:
    """Append-only AuditRepository backed by SQLAlchemy."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEvent) -> None:
        values = {
            "id": event.id.value,
            "category": event.category.value,
            "event_type": event.event_type,
            "occurred_at": event.occurred_at,
            "actor_id": event.actor_id,
            "subject_id": event.subject_id,
            "tenant_id": event.tenant_id,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "outcome": None if event.outcome is None else event.outcome.value,
            "reason_code": event.reason_code,
            "correlation_id": event.correlation_id,
            "metadata_json": ensure_json_mapping(event.metadata),
        }
        try:
            with self._session.begin_nested():
                self._session.execute(insert(audit_event_table).values(**values))
        except IntegrityError as exc:
            raise ValueError(f"Audit event {event.id} already exists") from exc

    def all(self) -> tuple[AuditEvent, ...]:
        rows = self._session.execute(
            select(audit_event_table).order_by(
                audit_event_table.c.occurred_at,
                audit_event_table.c.id,
            )
        ).mappings().all()
        return tuple(_audit_from_row(row) for row in rows)

    def by_correlation_id(self, correlation_id: str) -> tuple[AuditEvent, ...]:
        rows = self._session.execute(
            select(audit_event_table)
            .where(audit_event_table.c.correlation_id == correlation_id)
            .order_by(audit_event_table.c.occurred_at, audit_event_table.c.id)
        ).mappings().all()
        return tuple(_audit_from_row(row) for row in rows)

    def by_subject(self, subject_id: str) -> tuple[AuditEvent, ...]:
        rows = self._session.execute(
            select(audit_event_table)
            .where(audit_event_table.c.subject_id == subject_id)
            .order_by(audit_event_table.c.occurred_at, audit_event_table.c.id)
        ).mappings().all()
        return tuple(_audit_from_row(row) for row in rows)


def _audit_from_row(row: RowMapping) -> AuditEvent:
    outcome_value = row["outcome"]
    return AuditEvent(
        id=AuditEventId(uuid_from_db(row["id"])),
        category=AuditCategory(str(row["category"])),
        event_type=str(row["event_type"]),
        occurred_at=utc_from_db(row["occurred_at"]),
        actor_id=None if row["actor_id"] is None else str(row["actor_id"]),
        subject_id=None if row["subject_id"] is None else str(row["subject_id"]),
        tenant_id=None if row["tenant_id"] is None else str(row["tenant_id"]),
        action=None if row["action"] is None else str(row["action"]),
        resource_type=None if row["resource_type"] is None else str(row["resource_type"]),
        resource_id=None if row["resource_id"] is None else str(row["resource_id"]),
        outcome=None if outcome_value is None else AuditOutcome(str(outcome_value)),
        reason_code=None if row["reason_code"] is None else str(row["reason_code"]),
        correlation_id=(
            None if row["correlation_id"] is None else str(row["correlation_id"])
        ),
        metadata=mapping_from_json(row["metadata_json"]),
    )
