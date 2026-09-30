"""Cache-related operational value objects."""

import re
from dataclasses import dataclass

_NAMESPACE_PART_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class CacheNamespace:
    """Canonical namespace isolating operational data between applications."""

    application: str
    environment: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        application = self._normalize_part(self.application, field_name="application")
        environment = self._normalize_part(self.environment, field_name="environment")
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("CacheNamespace.schema_version must be an integer")
        if self.schema_version < 1:
            raise ValueError("CacheNamespace.schema_version must be greater than or equal to one")
        object.__setattr__(self, "application", application)
        object.__setattr__(self, "environment", environment)

    @property
    def prefix(self) -> str:
        """Return the canonical namespace prefix used by operational adapters."""

        return f"pyiamkit:{self.application}:{self.environment}:v{self.schema_version}"

    @staticmethod
    def _normalize_part(value: str, *, field_name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"CacheNamespace.{field_name} must be a string")
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError(f"CacheNamespace.{field_name} must not be empty")
        if not _NAMESPACE_PART_PATTERN.fullmatch(normalized):
            raise ValueError(f"CacheNamespace.{field_name} contains unsupported characters")
        return normalized
