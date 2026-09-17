"""Audit persistence and delivery ports."""

from typing import Protocol

from .domain import AuditEvent


class AuditSink(Protocol):
    """Append one immutable audit record."""

    def append(self, event: AuditEvent) -> None: ...


class AuditRepository(AuditSink, Protocol):
    """Append-only audit store with query capabilities."""

    def all(self) -> tuple[AuditEvent, ...]: ...
    def by_correlation_id(self, correlation_id: str) -> tuple[AuditEvent, ...]: ...
    def by_subject(self, subject_id: str) -> tuple[AuditEvent, ...]: ...
