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
    mfa_verified_at: datetime | None = None
    mfa_factor_id: str | None = None

    def __post_init__(self) -> None:
        if self.authenticated_at.tzinfo is None or self.authenticated_at.utcoffset() != timedelta(
            0
        ):
            raise ValueError("authenticated_at must be UTC-aware")

        if self.mfa_verified_at is not None:
            if self.mfa_verified_at.tzinfo is None or self.mfa_verified_at.utcoffset() != timedelta(
                0
            ):
                raise ValueError("mfa_verified_at must be UTC-aware")
            if self.mfa_verified_at < self.authenticated_at:
                raise ValueError("mfa_verified_at must not be before authenticated_at")

        for field_name in ("provider_id", "device_id", "network_zone", "mfa_factor_id"):
            value = getattr(self, field_name)
            if value is not None:
                normalized = value.strip()
                object.__setattr__(self, field_name, normalized or None)

        if self.mfa_factor_id is not None:
            if not self.mfa:
                raise ValueError("mfa_factor_id requires mfa=True")
            if self.mfa_verified_at is None:
                raise ValueError("mfa_factor_id requires mfa_verified_at")
