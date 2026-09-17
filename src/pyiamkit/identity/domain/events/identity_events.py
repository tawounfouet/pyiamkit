"""Names of events emitted by the Identity aggregate."""

from enum import StrEnum


class IdentityEventType(StrEnum):
    IDENTITY_CREATED = "IdentityCreated"
    IDENTITY_ACTIVATED = "IdentityActivated"
    IDENTITY_SUSPENDED = "IdentitySuspended"
    IDENTITY_REACTIVATED = "IdentityReactivated"
    IDENTITY_DISABLED = "IdentityDisabled"
    IDENTITY_ARCHIVED = "IdentityArchived"
    SERVICE_ACCOUNT_CREATED = "ServiceAccountCreated"
    EXTERNAL_IDENTITY_LINKED = "ExternalIdentityLinked"
    EXTERNAL_IDENTITY_UNLINKED = "ExternalIdentityUnlinked"
