from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.identity import (
    ExternalIdentityAlreadyLinked,
    IdentityApplicationService,
    IdentityId,
    IdentityNotFound,
    IdentityStatus,
)
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def make_service() -> tuple[
    IdentityApplicationService,
    InMemoryIdentityRepository,
    InMemoryDomainEventSink,
    FrozenClock,
]:
    repository = InMemoryIdentityRepository()
    event_sink = InMemoryDomainEventSink()
    clock = FrozenClock(NOW)
    service = IdentityApplicationService(
        repository=repository,
        clock=clock,
        event_sink=event_sink,
    )
    return service, repository, event_sink, clock


def test_create_user_persists_and_publishes_event() -> None:
    service, repository, event_sink, _ = make_service()

    identity = service.create_user(
        display_name="Alice",
        primary_email="Alice@Example.com",
        metadata={"source": "test"},
    )

    stored = repository.get(identity.id)
    assert stored is not None
    assert stored.status is IdentityStatus.PENDING
    assert str(stored.profile.primary_email) == "Alice@example.com"
    assert stored.metadata["source"] == "test"
    assert [event.event_type for event in event_sink.events] == ["IdentityCreated"]


def test_application_service_executes_full_lifecycle() -> None:
    service, repository, event_sink, clock = make_service()
    identity = service.create_user(display_name="Alice")

    clock.value = NOW + timedelta(minutes=1)
    service.activate_identity(identity.id)
    clock.value = NOW + timedelta(minutes=2)
    service.suspend_identity(identity.id)
    clock.value = NOW + timedelta(minutes=3)
    service.reactivate_identity(identity.id)
    clock.value = NOW + timedelta(minutes=4)
    service.disable_identity(identity.id, reason="offboarding")
    clock.value = NOW + timedelta(minutes=5)
    result = service.archive_identity(identity.id)

    assert result.status is IdentityStatus.ARCHIVED
    assert repository.get(identity.id).status is IdentityStatus.ARCHIVED  # type: ignore[union-attr]
    assert [event.event_type for event in event_sink.events] == [
        "IdentityCreated",
        "IdentityActivated",
        "IdentitySuspended",
        "IdentityReactivated",
        "IdentityDisabled",
        "IdentityArchived",
    ]


def test_unknown_identity_raises_not_found() -> None:
    service, _, _, _ = make_service()

    with pytest.raises(IdentityNotFound):
        service.activate_identity(IdentityId.new())


def test_service_account_owner_must_exist() -> None:
    service, _, _, _ = make_service()

    with pytest.raises(IdentityNotFound):
        service.create_service_account(
            display_name="Worker",
            name="worker",
            owner_identity_id=IdentityId.new(),
            purpose="sync",
        )


def test_create_service_account_with_existing_owner() -> None:
    service, repository, event_sink, _ = make_service()
    owner = service.create_user(display_name="Owner")

    worker = service.create_service_account(
        display_name="Billing Worker",
        name="billing-worker",
        owner_identity_id=owner.id,
        purpose="billing sync",
        environment="production",
    )

    assert repository.exists(worker.id)
    assert [event.event_type for event in event_sink.events][-2:] == [
        "IdentityCreated",
        "ServiceAccountCreated",
    ]


def test_external_identity_is_globally_unique_in_repository() -> None:
    service, _, _, _ = make_service()
    alice = service.create_user(display_name="Alice")
    bob = service.create_user(display_name="Bob")
    service.link_external_identity(
        alice.id,
        provider_id="entra",
        external_subject="subject-1",
    )

    with pytest.raises(ExternalIdentityAlreadyLinked):
        service.link_external_identity(
            bob.id,
            provider_id="entra",
            external_subject="subject-1",
        )


def test_application_service_can_unlink_external_identity() -> None:
    service, repository, _, _ = make_service()
    identity = service.create_user(display_name="Alice")
    service.link_external_identity(
        identity.id,
        provider_id="entra",
        external_subject="subject-1",
    )

    result = service.unlink_external_identity(
        identity.id,
        provider_id="entra",
        external_subject="subject-1",
    )

    assert result.external_links == ()
    assert repository.find_by_external_subject("entra", "subject-1") is None
