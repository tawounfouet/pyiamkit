"""Identity aggregate root."""

from collections.abc import Mapping
from datetime import datetime, timedelta
from types import MappingProxyType

from pyiamkit.shared import DomainEvent

from ..entities.external_identity_link import ExternalIdentityLink
from ..entities.service_account import ServiceAccount
from ..entities.user import User
from ..events.identity_events import IdentityEventType
from ..exceptions.identity_errors import (
    ExternalIdentityAlreadyLinked,
    ExternalIdentityLinkNotFound,
    InvalidDisplayName,
    InvalidIdentityTransition,
    InvalidServiceAccount,
)
from ..value_objects.email_address import EmailAddress
from ..value_objects.identity_id import IdentityId
from ..value_objects.identity_status import IdentityStatus
from ..value_objects.identity_type import IdentityType

IdentityProfile = User | ServiceAccount


class Identity:
    """Security principal lifecycle aggregate."""

    __slots__ = (
        "_activated_at",
        "_archived_at",
        "_created_at",
        "_disabled_at",
        "_display_name",
        "_external_links",
        "_id",
        "_metadata",
        "_pending_events",
        "_profile",
        "_status",
        "_suspended_at",
        "_type",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        identity_id: IdentityId,
        version: int,
        identity_type: IdentityType,
        status: IdentityStatus,
        display_name: str,
        profile: IdentityProfile,
        created_at: datetime,
        updated_at: datetime,
        activated_at: datetime | None = None,
        suspended_at: datetime | None = None,
        disabled_at: datetime | None = None,
        archived_at: datetime | None = None,
        external_links: tuple[ExternalIdentityLink, ...] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        self._require_utc(created_at, "created_at")
        self._require_utc(updated_at, "updated_at")
        for name, value in (
            ("activated_at", activated_at),
            ("suspended_at", suspended_at),
            ("disabled_at", disabled_at),
            ("archived_at", archived_at),
        ):
            if value is not None:
                self._require_utc(value, name)
        self._id = identity_id
        self._version = version
        self._type = identity_type
        self._status = status
        self._display_name = self._normalize_display_name(display_name)
        self._profile = profile
        self._validate_profile()
        self._created_at = created_at
        self._updated_at = updated_at
        self._activated_at = activated_at
        self._suspended_at = suspended_at
        self._disabled_at = disabled_at
        self._archived_at = archived_at
        self._external_links = list(external_links)
        self._metadata = MappingProxyType(dict(metadata or {}))
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create_user(
        cls,
        *,
        display_name: str,
        created_at: datetime,
        primary_email: EmailAddress | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> "Identity":
        identity = cls(
            identity_id=IdentityId.new(),
            version=0,
            identity_type=IdentityType.USER,
            status=IdentityStatus.PENDING,
            display_name=display_name,
            profile=User(primary_email=primary_email),
            created_at=created_at,
            updated_at=created_at,
            metadata=metadata,
        )
        identity._record(
            IdentityEventType.IDENTITY_CREATED,
            created_at,
            {"identity_id": str(identity.id), "identity_type": identity.type.value},
        )
        return identity

    @classmethod
    def create_service_account(
        cls,
        *,
        display_name: str,
        name: str,
        owner_identity_id: IdentityId,
        purpose: str,
        created_at: datetime,
        environment: str | None = None,
        expires_at: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> "Identity":
        identity_id = IdentityId.new()
        if owner_identity_id == identity_id:
            raise InvalidServiceAccount("Service account cannot own itself.")
        identity = cls(
            identity_id=identity_id,
            version=0,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            status=IdentityStatus.PENDING,
            display_name=display_name,
            profile=ServiceAccount(
                name=name,
                owner_identity_id=owner_identity_id,
                purpose=purpose,
                environment=environment,
                expires_at=expires_at,
            ),
            created_at=created_at,
            updated_at=created_at,
            metadata=metadata,
        )
        base_metadata = {
            "identity_id": str(identity.id),
            "identity_type": identity.type.value,
        }
        identity._record(IdentityEventType.IDENTITY_CREATED, created_at, base_metadata)
        identity._record(
            IdentityEventType.SERVICE_ACCOUNT_CREATED,
            created_at,
            {**base_metadata, "owner_identity_id": str(owner_identity_id)},
        )
        return identity

    @classmethod
    def _rehydrate(
        cls,
        *,
        identity_id: IdentityId,
        version: int,
        identity_type: IdentityType,
        status: IdentityStatus,
        display_name: str,
        profile: IdentityProfile,
        created_at: datetime,
        updated_at: datetime,
        activated_at: datetime | None,
        suspended_at: datetime | None,
        disabled_at: datetime | None,
        archived_at: datetime | None,
        external_links: tuple[ExternalIdentityLink, ...],
        metadata: Mapping[str, object],
    ) -> "Identity":
        return cls(
            identity_id=identity_id,
            version=version,
            identity_type=identity_type,
            status=status,
            display_name=display_name,
            profile=profile,
            created_at=created_at,
            updated_at=updated_at,
            activated_at=activated_at,
            suspended_at=suspended_at,
            disabled_at=disabled_at,
            archived_at=archived_at,
            external_links=external_links,
            metadata=metadata,
        )

    @property
    def id(self) -> IdentityId:
        return self._id

    @property
    def version(self) -> int:
        return self._version

    @property
    def type(self) -> IdentityType:
        return self._type

    @property
    def status(self) -> IdentityStatus:
        return self._status

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def profile(self) -> IdentityProfile:
        return self._profile

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def activated_at(self) -> datetime | None:
        return self._activated_at

    @property
    def suspended_at(self) -> datetime | None:
        return self._suspended_at

    @property
    def disabled_at(self) -> datetime | None:
        return self._disabled_at

    @property
    def archived_at(self) -> datetime | None:
        return self._archived_at

    @property
    def metadata(self) -> Mapping[str, object]:
        return self._metadata

    @property
    def external_links(self) -> tuple[ExternalIdentityLink, ...]:
        return tuple(self._external_links)

    def activate(self, *, at: datetime) -> None:
        self._require_status(IdentityStatus.PENDING, "activate")
        self._require_utc(at, "at")
        self._status = IdentityStatus.ACTIVE
        self._activated_at = at
        self._touch(at)
        self._record(IdentityEventType.IDENTITY_ACTIVATED, at)

    def suspend(self, *, at: datetime) -> None:
        self._require_status(IdentityStatus.ACTIVE, "suspend")
        self._require_utc(at, "at")
        self._status = IdentityStatus.SUSPENDED
        self._suspended_at = at
        self._touch(at)
        self._record(IdentityEventType.IDENTITY_SUSPENDED, at)

    def reactivate(self, *, at: datetime) -> None:
        self._require_status(IdentityStatus.SUSPENDED, "reactivate")
        self._require_utc(at, "at")
        self._status = IdentityStatus.ACTIVE
        self._suspended_at = None
        self._touch(at)
        self._record(IdentityEventType.IDENTITY_REACTIVATED, at)

    def disable(self, *, at: datetime, reason: str | None = None) -> None:
        if self.status not in {IdentityStatus.ACTIVE, IdentityStatus.SUSPENDED}:
            raise InvalidIdentityTransition(self.status, "disable")
        self._require_utc(at, "at")
        self._status = IdentityStatus.DISABLED
        self._disabled_at = at
        self._touch(at)
        metadata: dict[str, object] = {}
        if reason is not None:
            metadata["reason"] = reason
        self._record(IdentityEventType.IDENTITY_DISABLED, at, metadata)

    def archive(self, *, at: datetime) -> None:
        self._require_status(IdentityStatus.DISABLED, "archive")
        self._require_utc(at, "at")
        self._status = IdentityStatus.ARCHIVED
        self._archived_at = at
        self._touch(at)
        self._record(IdentityEventType.IDENTITY_ARCHIVED, at)

    def link_external_identity(
        self,
        *,
        provider_id: str,
        external_subject: str,
        at: datetime,
    ) -> None:
        link = ExternalIdentityLink(provider_id, external_subject, at)
        if any(
            existing.provider_id == link.provider_id
            and existing.external_subject == link.external_subject
            for existing in self._external_links
        ):
            raise ExternalIdentityAlreadyLinked(link.provider_id, link.external_subject)
        self._external_links.append(link)
        self._touch(at)
        self._record(
            IdentityEventType.EXTERNAL_IDENTITY_LINKED,
            at,
            {"provider_id": link.provider_id, "external_subject": link.external_subject},
        )

    def unlink_external_identity(
        self,
        *,
        provider_id: str,
        external_subject: str,
        at: datetime,
    ) -> None:
        self._require_utc(at, "at")
        provider = provider_id.strip()
        subject = external_subject.strip()
        for index, link in enumerate(self._external_links):
            if link.provider_id == provider and link.external_subject == subject:
                self._external_links.pop(index)
                self._touch(at)
                self._record(
                    IdentityEventType.EXTERNAL_IDENTITY_UNLINKED,
                    at,
                    {"provider_id": link.provider_id, "external_subject": link.external_subject},
                )
                return
        raise ExternalIdentityLinkNotFound(provider_id, external_subject)

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _touch(self, at: datetime) -> None:
        self._version += 1
        self._updated_at = at

    def _record(
        self,
        event_type: IdentityEventType,
        at: datetime,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        payload = {"identity_id": str(self.id), **dict(metadata or {})}
        self._pending_events.append(
            DomainEvent(event_type=event_type.value, occurred_at=at, metadata=payload)
        )

    def _require_status(self, expected: IdentityStatus, action: str) -> None:
        if self.status is not expected:
            raise InvalidIdentityTransition(self.status.value, action)

    def _validate_profile(self) -> None:
        if self.type is IdentityType.USER and not isinstance(self.profile, User):
            raise TypeError("USER identities require a User profile.")
        if self.type is IdentityType.SERVICE_ACCOUNT and not isinstance(
            self.profile, ServiceAccount
        ):
            raise TypeError("SERVICE_ACCOUNT identities require a ServiceAccount profile.")
        if isinstance(self.profile, ServiceAccount) and self.profile.owner_identity_id == self.id:
            raise InvalidServiceAccount("Service account cannot own itself.")

    @staticmethod
    def _normalize_display_name(value: str) -> str:
        normalized = value.strip()
        if not 1 <= len(normalized) <= 255:
            raise InvalidDisplayName()
        return normalized

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None or offset != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Identity):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)
