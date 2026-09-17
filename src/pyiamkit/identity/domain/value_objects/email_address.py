"""Email address value object."""

from dataclasses import dataclass

from ..exceptions.identity_errors import InvalidEmailAddress


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """A deliberately small, non-RFC-exhaustive email value object."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip()
        local, separator, domain = normalized.partition("@")
        if (
            not separator
            or not local
            or not domain
            or " " in normalized
            or "." not in domain
            or len(normalized) > 320
        ):
            raise InvalidEmailAddress(normalized)
        object.__setattr__(self, "value", f"{local}@{domain.lower()}")

    @classmethod
    def parse(cls, value: str) -> "EmailAddress":
        return cls(value)

    def __str__(self) -> str:
        return self.value
