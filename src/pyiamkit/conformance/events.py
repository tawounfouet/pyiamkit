"""Reusable event-publisher conformance suite."""

from collections.abc import Callable
from dataclasses import dataclass

from .report import ConformanceCheck, ConformanceReport


@dataclass(frozen=True, slots=True)
class EventPublisherProbe:
    """Scenarios used to qualify durable-event publisher adapters."""

    name: str
    publish_once: Callable[[], tuple[str, str]]
    publish_duplicate: Callable[[], tuple[str, tuple[str, ...]]]
    invalid_event: Callable[[], None]
    downstream_failure: Callable[[], None]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("EventPublisherProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class EventPublisherConformance:
    """Qualify event identity preservation and fail-closed publication behavior."""

    suite_name = "EventPublisherConformance"

    def __init__(self, probe: EventPublisherProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("event_identity_preserved", self._event_identity_preserved),
                self._check(
                    "duplicate_delivery_preserves_identity",
                    self._duplicate_delivery_preserves_identity,
                ),
                self._check("invalid_event_rejected", self._invalid_event_rejected),
                self._check(
                    "downstream_failure_propagates",
                    self._downstream_failure_propagates,
                ),
            ),
        )

    def _event_identity_preserved(self) -> None:
        expected, observed = self._probe.publish_once()
        if observed != expected:
            raise AssertionError(
                f"publisher changed event identity: expected {expected!r}, got {observed!r}"
            )

    def _duplicate_delivery_preserves_identity(self) -> None:
        expected, observed = self._probe.publish_duplicate()
        if len(observed) != 2:
            raise AssertionError(f"expected two deliveries, got {len(observed)}")
        if any(event_id != expected for event_id in observed):
            raise AssertionError("duplicate delivery changed canonical event identity")

    def _invalid_event_rejected(self) -> None:
        try:
            self._probe.invalid_event()
        except (TypeError, ValueError):
            return
        raise AssertionError("invalid event was accepted")

    def _downstream_failure_propagates(self) -> None:
        try:
            self._probe.downstream_failure()
        except Exception:
            return
        raise AssertionError("downstream failure was swallowed")

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)
