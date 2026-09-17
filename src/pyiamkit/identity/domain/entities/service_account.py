"""Service-account profile."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..exceptions.identity_errors import InvalidServiceAccount
from ..value_objects.identity_id import IdentityId


@dataclass(frozen=True, slots=True)
class ServiceAccount:
    """Non-human profile attached to an Identity aggregate."""

    name: str
    owner_identity_id: IdentityId
    purpose: str
    environment: str | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        purpose = self.purpose.strip()
        if not name:
            raise InvalidServiceAccount("Service account name must not be empty.")
        if not purpose:
            raise InvalidServiceAccount("Service account purpose must not be empty.")
        if self.expires_at is not None:
            offset = self.expires_at.utcoffset()
            if self.expires_at.tzinfo is None or offset is None or offset != timedelta(0):
                raise InvalidServiceAccount("Service account expiry must be UTC-aware.")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "purpose", purpose)
