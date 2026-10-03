"""Application service that drains durable outbox publication intents."""

from dataclasses import dataclass

from pyiamkit.shared import Clock, SystemClock

from .outbox import OutboxEventId
from .ports import EventPublisher, OutboxRepository


@dataclass(frozen=True, slots=True)
class OutboxPublishBatchResult:
    """Summary of one bounded outbox publication pass."""

    selected: int
    published: int
    failed: int
    failed_event_ids: tuple[OutboxEventId, ...]

    @property
    def attempted(self) -> int:
        return self.published + self.failed


class OutboxPublisher:
    """Publish committed outbox events with explicit at-least-once semantics."""

    def __init__(
        self,
        *,
        repository: OutboxRepository,
        publisher: EventPublisher,
        clock: Clock | None = None,
    ) -> None:
        self._repository = repository
        self._publisher = publisher
        self._clock = SystemClock() if clock is None else clock

    def publish_batch(self, *, limit: int = 100) -> OutboxPublishBatchResult:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be an integer >= 1")

        events = self._repository.deliverable(limit=limit)
        published = 0
        failed_ids: list[OutboxEventId] = []

        for event in events:
            try:
                self._publisher.publish(event)
            except Exception:
                self._repository.mark_failed(event.id)
                failed_ids.append(event.id)
                continue

            self._repository.mark_published(
                event.id,
                published_at=self._clock.now(),
            )
            published += 1

        return OutboxPublishBatchResult(
            selected=len(events),
            published=published,
            failed=len(failed_ids),
            failed_event_ids=tuple(failed_ids),
        )
