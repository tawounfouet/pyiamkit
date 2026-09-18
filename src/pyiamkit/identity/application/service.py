"""Application orchestration for the Identity bounded context."""

from collections.abc import Mapping
from datetime import datetime

from pyiamkit.shared import Clock

from ..domain.aggregates.identity import Identity
from ..domain.exceptions.identity_errors import (
    ExternalIdentityAlreadyLinked,
    IdentityNotFound,
)
from ..domain.value_objects.email_address import EmailAddress
from ..domain.value_objects.identity_id import IdentityId
from ..ports.events import DomainEventSink
from ..ports.repositories import IdentityRepository


class IdentityApplicationService:
    """Small application service for the `0.1.0a1` Identity use cases."""

    def __init__(
        self,
        *,
        repository: IdentityRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._event_sink = event_sink

    def create_user(
        self,
        *,
        display_name: str,
        primary_email: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Identity:
        email = None if primary_email is None else EmailAddress.parse(primary_email)
        identity = Identity.create_user(
            display_name=display_name,
            primary_email=email,
            created_at=self._clock.now(),
            metadata=metadata,
        )
        return self._save_and_publish(identity)

    def update_user_profile(
        self,
        identity_id: IdentityId,
        *,
        display_name: str,
        primary_email: str | None = None,
        email_verified: bool = False,
        first_name: str | None = None,
        last_name: str | None = None,
        locale: str | None = None,
        timezone: str | None = None,
    ) -> Identity:
        identity = self._get_required(identity_id)
        email = None if primary_email is None else EmailAddress.parse(primary_email)
        identity.update_user_profile(
            display_name=display_name,
            primary_email=email,
            email_verified=email_verified,
            first_name=first_name,
            last_name=last_name,
            locale=locale,
            timezone=timezone,
            at=self._clock.now(),
        )
        return self._save_and_publish(identity)

    def create_service_account(
        self,
        *,
        display_name: str,
        name: str,
        owner_identity_id: IdentityId,
        purpose: str,
        environment: str | None = None,
        expires_at: datetime | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Identity:
        self._get_required(owner_identity_id)
        identity = Identity.create_service_account(
            display_name=display_name,
            name=name,
            owner_identity_id=owner_identity_id,
            purpose=purpose,
            created_at=self._clock.now(),
            environment=environment,
            expires_at=expires_at,
            metadata=metadata,
        )
        return self._save_and_publish(identity)

    def activate_identity(self, identity_id: IdentityId) -> Identity:
        identity = self._get_required(identity_id)
        identity.activate(at=self._clock.now())
        return self._save_and_publish(identity)

    def suspend_identity(self, identity_id: IdentityId) -> Identity:
        identity = self._get_required(identity_id)
        identity.suspend(at=self._clock.now())
        return self._save_and_publish(identity)

    def reactivate_identity(self, identity_id: IdentityId) -> Identity:
        identity = self._get_required(identity_id)
        identity.reactivate(at=self._clock.now())
        return self._save_and_publish(identity)

    def disable_identity(
        self,
        identity_id: IdentityId,
        *,
        reason: str | None = None,
    ) -> Identity:
        identity = self._get_required(identity_id)
        identity.disable(at=self._clock.now(), reason=reason)
        return self._save_and_publish(identity)

    def archive_identity(self, identity_id: IdentityId) -> Identity:
        identity = self._get_required(identity_id)
        identity.archive(at=self._clock.now())
        return self._save_and_publish(identity)

    def link_external_identity(
        self,
        identity_id: IdentityId,
        *,
        provider_id: str,
        external_subject: str,
    ) -> Identity:
        identity = self._get_required(identity_id)
        existing = self._repository.find_by_external_subject(provider_id, external_subject)
        if existing is not None and existing.id != identity.id:
            raise ExternalIdentityAlreadyLinked(provider_id, external_subject)
        identity.link_external_identity(
            provider_id=provider_id,
            external_subject=external_subject,
            at=self._clock.now(),
        )
        return self._save_and_publish(identity)

    def unlink_external_identity(
        self,
        identity_id: IdentityId,
        *,
        provider_id: str,
        external_subject: str,
    ) -> Identity:
        identity = self._get_required(identity_id)
        identity.unlink_external_identity(
            provider_id=provider_id,
            external_subject=external_subject,
            at=self._clock.now(),
        )
        return self._save_and_publish(identity)

    def _get_required(self, identity_id: IdentityId) -> Identity:
        identity = self._repository.get(identity_id)
        if identity is None:
            raise IdentityNotFound(identity_id)
        return identity

    def _save_and_publish(self, identity: Identity) -> Identity:
        self._repository.save(identity)
        self._event_sink.publish(identity.pull_events())
        return identity
