"""Membership aggregate root."""

from datetime import datetime, timedelta

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent

from .errors import InvalidMembership, InvalidMembershipTransition
from .events import TenancyEventType
from .value_objects import MembershipId, MembershipStatus, OrganizationId, TenantId


class Membership:
    __slots__ = (
        "_id", "_version", "_identity_id", "_tenant_id", "_organization_id",
        "_status", "_source", "_created_at", "_updated_at", "_valid_from",
        "_valid_until", "_pending_events",
    )

    def __init__(self, *, membership_id: MembershipId, version: int,
                 identity_id: IdentityId, tenant_id: TenantId,
                 organization_id: OrganizationId | None, status: MembershipStatus,
                 source: str, created_at: datetime, updated_at: datetime,
                 valid_from: datetime, valid_until: datetime | None) -> None:
        for name, value in (("created_at", created_at), ("updated_at", updated_at),
                            ("valid_from", valid_from)):
            self._require_utc(value, name)
        if valid_until is not None:
            self._require_utc(valid_until, "valid_until")
            if valid_until <= valid_from:
                raise InvalidMembership("valid_until must be after valid_from.")
        source = source.strip()
        if not source:
            raise InvalidMembership("Membership source must not be empty.")
        self._id = membership_id
        self._version = version
        self._identity_id = identity_id
        self._tenant_id = tenant_id
        self._organization_id = organization_id
        self._status = status
        self._source = source
        self._created_at = created_at
        self._updated_at = updated_at
        self._valid_from = valid_from
        self._valid_until = valid_until
        self._pending_events: list[DomainEvent] = []

    @classmethod
    def create(cls, *, identity_id: IdentityId, tenant_id: TenantId,
               created_at: datetime, organization_id: OrganizationId | None = None,
               valid_from: datetime | None = None, valid_until: datetime | None = None,
               source: str = "direct") -> "Membership":
        membership = cls(membership_id=MembershipId.new(), version=0,
            identity_id=identity_id, tenant_id=tenant_id, organization_id=organization_id,
            status=MembershipStatus.PENDING, source=source, created_at=created_at,
            updated_at=created_at, valid_from=valid_from or created_at,
            valid_until=valid_until)
        membership._record(TenancyEventType.MEMBERSHIP_CREATED, created_at)
        return membership

    @classmethod
    def _rehydrate(cls, *, membership_id: MembershipId, version: int,
                   identity_id: IdentityId, tenant_id: TenantId,
                   organization_id: OrganizationId | None, status: MembershipStatus,
                   source: str, created_at: datetime, updated_at: datetime,
                   valid_from: datetime, valid_until: datetime | None) -> "Membership":
        return cls(membership_id=membership_id, version=version,
            identity_id=identity_id, tenant_id=tenant_id, organization_id=organization_id,
            status=status, source=source, created_at=created_at, updated_at=updated_at,
            valid_from=valid_from, valid_until=valid_until)

    @property
    def id(self) -> MembershipId: return self._id
    @property
    def version(self) -> int: return self._version
    @property
    def identity_id(self) -> IdentityId: return self._identity_id
    @property
    def tenant_id(self) -> TenantId: return self._tenant_id
    @property
    def organization_id(self) -> OrganizationId | None: return self._organization_id
    @property
    def status(self) -> MembershipStatus: return self._status
    @property
    def source(self) -> str: return self._source
    @property
    def created_at(self) -> datetime: return self._created_at
    @property
    def updated_at(self) -> datetime: return self._updated_at
    @property
    def valid_from(self) -> datetime: return self._valid_from
    @property
    def valid_until(self) -> datetime | None: return self._valid_until

    def activate(self, *, at: datetime) -> None:
        self._transition(MembershipStatus.PENDING, MembershipStatus.ACTIVE, "activate", at,
                         TenancyEventType.MEMBERSHIP_ACTIVATED)

    def suspend(self, *, at: datetime) -> None:
        self._transition(MembershipStatus.ACTIVE, MembershipStatus.SUSPENDED, "suspend", at,
                         TenancyEventType.MEMBERSHIP_SUSPENDED)

    def reactivate(self, *, at: datetime) -> None:
        self._transition(MembershipStatus.SUSPENDED, MembershipStatus.ACTIVE, "reactivate", at,
                         TenancyEventType.MEMBERSHIP_REACTIVATED)

    def expire(self, *, at: datetime) -> None:
        if self.status not in {MembershipStatus.PENDING, MembershipStatus.ACTIVE,
                               MembershipStatus.SUSPENDED}:
            raise InvalidMembershipTransition(self.status.value, "expire")
        self._set_status(MembershipStatus.EXPIRED, at, TenancyEventType.MEMBERSHIP_EXPIRED)

    def revoke(self, *, at: datetime) -> None:
        if self.status not in {MembershipStatus.PENDING, MembershipStatus.ACTIVE,
                               MembershipStatus.SUSPENDED}:
            raise InvalidMembershipTransition(self.status.value, "revoke")
        self._set_status(MembershipStatus.REVOKED, at, TenancyEventType.MEMBERSHIP_REVOKED)

    def is_active(self, *, at: datetime) -> bool:
        self._require_utc(at, "at")
        return (self.status is MembershipStatus.ACTIVE and self.valid_from <= at and
                (self.valid_until is None or at < self.valid_until))

    def pull_events(self) -> tuple[DomainEvent, ...]:
        events = tuple(self._pending_events)
        self._pending_events.clear()
        return events

    def _transition(self, expected: MembershipStatus, target: MembershipStatus, action: str,
                    at: datetime, event_type: TenancyEventType) -> None:
        if self.status is not expected:
            raise InvalidMembershipTransition(self.status.value, action)
        self._set_status(target, at, event_type)

    def _set_status(self, status: MembershipStatus, at: datetime,
                    event_type: TenancyEventType) -> None:
        self._require_utc(at, "at")
        self._status = status
        self._version += 1
        self._updated_at = at
        self._record(event_type, at)

    def _record(self, event_type: TenancyEventType, at: datetime) -> None:
        self._pending_events.append(DomainEvent(event_type=event_type.value, occurred_at=at,
            metadata={"membership_id": str(self.id), "identity_id": str(self.identity_id),
                      "tenant_id": str(self.tenant_id)}))

    @staticmethod
    def _require_utc(value: datetime, name: str) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{name} must be UTC-aware")
