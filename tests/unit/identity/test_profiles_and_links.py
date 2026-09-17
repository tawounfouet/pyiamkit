from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.identity import (
    Identity,
    IdentityId,
    IdentityStatus,
    IdentityType,
    InvalidServiceAccount,
)
from pyiamkit.identity.domain.entities import ServiceAccount
from pyiamkit.identity.domain.exceptions import (
    ExternalIdentityAlreadyLinked,
    ExternalIdentityLinkNotFound,
    InvalidExternalIdentity,
)

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_service_account_has_expected_profile_and_events() -> None:
    owner_id = IdentityId.new()
    identity = Identity.create_service_account(
        display_name="Billing Worker",
        name=" billing-worker ",
        owner_identity_id=owner_id,
        purpose=" Billing synchronization ",
        created_at=NOW,
        environment="production",
        expires_at=NOW + timedelta(days=30),
    )

    assert identity.type is IdentityType.SERVICE_ACCOUNT
    assert isinstance(identity.profile, ServiceAccount)
    assert identity.profile.name == "billing-worker"
    assert identity.profile.purpose == "Billing synchronization"
    assert identity.profile.owner_identity_id == owner_id
    assert [event.event_type for event in identity.pull_events()] == [
        "IdentityCreated",
        "ServiceAccountCreated",
    ]


def test_service_account_requires_name_and_purpose() -> None:
    owner_id = IdentityId.new()
    with pytest.raises(InvalidServiceAccount):
        Identity.create_service_account(
            display_name="Worker",
            name=" ",
            owner_identity_id=owner_id,
            purpose="sync",
            created_at=NOW,
        )
    with pytest.raises(InvalidServiceAccount):
        Identity.create_service_account(
            display_name="Worker",
            name="worker",
            owner_identity_id=owner_id,
            purpose=" ",
            created_at=NOW,
        )


def test_service_account_expiry_must_be_utc() -> None:
    with pytest.raises(InvalidServiceAccount):
        ServiceAccount(
            name="worker",
            owner_identity_id=IdentityId.new(),
            purpose="sync",
            expires_at=datetime(2026, 10, 1, 12, 0),
        )


def test_identity_rejects_self_owned_service_account_on_rehydration() -> None:
    identity_id = IdentityId.new()
    profile = ServiceAccount(
        name="worker",
        owner_identity_id=identity_id,
        purpose="sync",
    )
    with pytest.raises(InvalidServiceAccount, match="own itself"):
        Identity._rehydrate(
            identity_id=identity_id,
            version=0,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            status=IdentityStatus.PENDING,
            display_name="Worker",
            profile=profile,
            created_at=NOW,
            updated_at=NOW,
            activated_at=None,
            suspended_at=None,
            disabled_at=None,
            archived_at=None,
            external_links=(),
            metadata={},
        )


def test_external_identity_link_and_unlink() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.pull_events()

    identity.link_external_identity(
        provider_id=" entra ",
        external_subject=" subject-1 ",
        at=NOW,
    )
    assert len(identity.external_links) == 1
    assert identity.external_links[0].provider_id == "entra"

    with pytest.raises(ExternalIdentityAlreadyLinked):
        identity.link_external_identity(
            provider_id="entra",
            external_subject="subject-1",
            at=NOW,
        )

    identity.unlink_external_identity(
        provider_id="entra",
        external_subject="subject-1",
        at=NOW,
    )
    assert identity.external_links == ()
    assert [event.event_type for event in identity.pull_events()] == [
        "ExternalIdentityLinked",
        "ExternalIdentityUnlinked",
    ]


def test_unlink_missing_external_identity_is_strict() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)

    with pytest.raises(ExternalIdentityLinkNotFound):
        identity.unlink_external_identity(
            provider_id="entra",
            external_subject="missing",
            at=NOW,
        )


def test_external_identity_rejects_blank_or_non_utc_values() -> None:
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    with pytest.raises(InvalidExternalIdentity):
        identity.link_external_identity(provider_id=" ", external_subject="x", at=NOW)
    with pytest.raises(InvalidExternalIdentity):
        identity.link_external_identity(
            provider_id="entra",
            external_subject="x",
            at=datetime(2026, 9, 17, 12, 0),
        )
