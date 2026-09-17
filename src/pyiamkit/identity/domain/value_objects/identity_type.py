"""Identity types."""

from enum import StrEnum


class IdentityType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
