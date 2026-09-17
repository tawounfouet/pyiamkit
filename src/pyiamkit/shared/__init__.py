"""Minimal shared-kernel primitives for PyIAMKit."""

from .errors import DomainError, PyIAMKitError
from .events import DomainEvent
from .ids import EntityId
from .time import Clock, SystemClock

__all__ = [
    "Clock",
    "DomainError",
    "DomainEvent",
    "EntityId",
    "PyIAMKitError",
    "SystemClock",
]
