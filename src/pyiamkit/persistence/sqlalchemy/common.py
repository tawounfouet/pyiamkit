"""Shared helpers used by SQLAlchemy persistence adapters."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import Table, insert, literal, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from pyiamkit.persistence import PersistenceSerializationError


def ensure_json_mapping(value: Mapping[str, object]) -> dict[str, object]:
    """Return a detached JSON-safe dictionary or fail at the adapter boundary."""

    payload = dict(value)
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise PersistenceSerializationError("Metadata must be JSON serializable.") from exc
    return payload


def mapping_from_json(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PersistenceSerializationError("Stored JSON payload is not a mapping.")
    return {str(key): item for key, item in value.items()}


def uuid_from_db(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def utc_from_db(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("Expected a datetime value from persistence.")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def optional_utc_from_db(value: object | None) -> datetime | None:
    return None if value is None else utc_from_db(value)


def optional_uuid_from_db(value: object | None) -> UUID | None:
    return None if value is None else uuid_from_db(value)


def decimal_from_db(value: object) -> Decimal:
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def upsert(
    session: Session,
    table: Table,
    predicate: ColumnElement[bool],
    values: Mapping[str, Any],
) -> None:
    """Portable insert-or-update used instead of dialect-specific UPSERT syntax."""

    exists = session.execute(
        select(literal(1)).select_from(table).where(predicate).limit(1)
    ).first()
    payload = dict(values)
    if exists is None:
        session.execute(insert(table).values(**payload))
    else:
        session.execute(update(table).where(predicate).values(**payload))
