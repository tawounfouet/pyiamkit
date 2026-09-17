"""Typed identifier primitives."""

from dataclasses import dataclass
from typing import Self
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class EntityId:
    """Opaque immutable identifier backed by a UUID."""

    value: UUID

    @classmethod
    def new(cls) -> Self:
        """Create a new identifier."""

        return cls(uuid4())

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse an identifier from its canonical string representation."""

        return cls(UUID(value))

    def __str__(self) -> str:
        return str(self.value)
