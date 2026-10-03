"""Transactional outbox domain objects."""

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from pyiamkit.shared import EntityId


class OutboxEventId(EntityId):
    """Stable identifier for one durable publication intent."""


class OutboxStatus(StrEnum):
    """Durable publication state."""

    PENDING = "pending"
    PUBLISHED = "published"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    """Immutable durable publication intent written in the business transaction."""

    event_type: str
    occurred_at: datetime
    payload: Mapping[str, object]
    id: OutboxEventId = field(default_factory=OutboxEventId.new)
    event_version: int = 1
    aggregate_type: str | None = None
    aggregate_id: str | None = None
    aggregate_version: int | None = None
    tenant_id: str | None = None
    published_at: datetime | None = None
    attempts: int = 0
    status: OutboxStatus = OutboxStatus.PENDING

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise ValueError("OutboxEvent.occurred_at must be UTC-aware")
        if self.published_at is not None and (
            self.published_at.tzinfo is None or self.published_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("OutboxEvent.published_at must be UTC-aware when provided")

        event_type = self.event_type.strip()
        if not event_type:
            raise ValueError("OutboxEvent.event_type must not be empty")
        if (
            not isinstance(self.event_version, int)
            or isinstance(self.event_version, bool)
            or self.event_version < 1
        ):
            raise ValueError("OutboxEvent.event_version must be an integer >= 1")
        if self.aggregate_version is not None and (
            not isinstance(self.aggregate_version, int)
            or isinstance(self.aggregate_version, bool)
            or self.aggregate_version < 0
        ):
            raise ValueError("OutboxEvent.aggregate_version must be an integer >= 0")
        if (
            not isinstance(self.attempts, int)
            or isinstance(self.attempts, bool)
            or self.attempts < 0
        ):
            raise ValueError("OutboxEvent.attempts must be an integer >= 0")
        if not isinstance(self.status, OutboxStatus):
            raise TypeError("OutboxEvent.status must be an OutboxStatus")
        if self.status is OutboxStatus.PUBLISHED and self.published_at is None:
            raise ValueError("Published OutboxEvent requires published_at")
        if self.status is not OutboxStatus.PUBLISHED and self.published_at is not None:
            raise ValueError("Only published OutboxEvent may define published_at")

        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(
            self,
            "aggregate_type",
            self._optional_text(self.aggregate_type, "aggregate_type"),
        )
        object.__setattr__(
            self,
            "aggregate_id",
            self._optional_text(self.aggregate_id, "aggregate_id"),
        )
        object.__setattr__(self, "tenant_id", self._optional_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    @property
    def deliverable(self) -> bool:
        """Whether this durable intent may be attempted by an outbox worker."""

        return self.status in {OutboxStatus.PENDING, OutboxStatus.FAILED}

    def record_published(self, *, published_at: datetime) -> "OutboxEvent":
        """Return the successful delivery state after one external publish attempt."""

        if not self.deliverable:
            raise ValueError("Published OutboxEvent cannot be delivered again")
        return replace(
            self,
            published_at=published_at,
            attempts=self.attempts + 1,
            status=OutboxStatus.PUBLISHED,
        )

    def record_failed(self) -> "OutboxEvent":
        """Return the retryable failed state after one external publish attempt."""

        if not self.deliverable:
            raise ValueError("Published OutboxEvent cannot be marked failed")
        return replace(
            self,
            published_at=None,
            attempts=self.attempts + 1,
            status=OutboxStatus.FAILED,
        )

    @staticmethod
    def _optional_text(value: str | None, field_name: str) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError(f"OutboxEvent.{field_name} must not be empty when provided")
        return normalized
