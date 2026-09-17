"""External identity link entity."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..exceptions.identity_errors import InvalidExternalIdentity


@dataclass(frozen=True, slots=True)
class ExternalIdentityLink:
    """Link between an internal Identity and an external provider subject."""

    provider_id: str
    external_subject: str
    linked_at: datetime

    def __post_init__(self) -> None:
        provider_id = self.provider_id.strip()
        external_subject = self.external_subject.strip()
        offset = self.linked_at.utcoffset()
        if not provider_id or not external_subject:
            raise InvalidExternalIdentity("Provider and external subject must not be empty.")
        if self.linked_at.tzinfo is None or offset is None or offset != timedelta(0):
            raise InvalidExternalIdentity("External identity link timestamp must be UTC-aware.")
        object.__setattr__(self, "provider_id", provider_id)
        object.__setattr__(self, "external_subject", external_subject)
