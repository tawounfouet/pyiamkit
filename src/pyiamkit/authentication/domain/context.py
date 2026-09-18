"""Authentication context carried by an established session."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from .value_objects import AssuranceLevel, AuthenticationMethod


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    method: AuthenticationMethod
    assurance_level: AssuranceLevel
    mfa: bool
    authenticated_at: datetime
    provider_id: str | None = None
    device_id: str | None = None
    network_zone: str | None = None

    def __post_init__(self) -> None:
        if (
            self.authenticated_at.tzinfo is None
            or self.authenticated_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("authenticated_at must be UTC-aware")
        for field_name in ("provider_id", "device_id", "network_zone"):
            value = getattr(self, field_name)
            if value is not None:
                normalized = value.strip()
                object.__setattr__(self, field_name, normalized or None)
