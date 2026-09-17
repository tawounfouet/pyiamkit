"""Permission catalog entry."""

from dataclasses import dataclass

from .value_objects import PermissionCode


@dataclass(frozen=True, slots=True)
class Permission:
    """Immutable capability definition independent from subjects and roles."""

    code: PermissionCode
    description: str = ""
    sensitive: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "description", self.description.strip())
