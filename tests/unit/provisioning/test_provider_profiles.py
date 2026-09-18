from datetime import UTC, datetime

import pytest

from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.provisioning import InvalidScimRequest, ProvisioningSource, ScimProvisioningService
from pyiamkit.provisioning.adapters import InMemoryProvisioningUserRepository
from pyiamkit.provisioning.http import (
    SCIM_USER_SCHEMA,
    ScimHttpTransport,
    parse_user_filter,
    parse_user_filter_expression,
)
from pyiamkit.provisioning.providers import (
    GENERIC_SCIM_PROFILE,
    MICROSOFT_ENTRA_PROFILE,
    OKTA_SCIM_PROFILE,
    ScimProviderKind,
    ScimProviderProfile,
    scim_provider_profile,
)
from pyiamkit.tenancy import TenancyApplicationService
from pyiamkit.tenancy.adapters import (
    InMemoryMembershipRepository,
    InMemoryTenantRepository,
)

NOW = datetime(2026, 9, 18, 10, 30, tzinfo=UTC)


class FrozenClock:
    def now(self) -> datetime:
        return NOW


def _transport(profile: ScimProviderProfile) -> ScimHttpTransport:
    clock = FrozenClock()
    events = InMemoryDomainEventSink()
    identities = InMemoryIdentityRepository()
    tenants = InMemoryTenantRepository()
    memberships = InMemoryMembershipRepository()

    identity_service = IdentityApplicationService(
        repository=identities,
        clock=clock,
        event_sink=events,
    )
    tenancy_service = TenancyApplicationService(
        tenant_repository=tenants,
        membership_repository=memberships,
        identity_repository=identities,
        clock=clock,
        event_sink=events,
    )
    tenant = tenancy_service.create_tenant(name="ACME", slug="acme")
    tenant = tenancy_service.activate_tenant(tenant.id)

    provisioning = ScimProvisioningService(
        source=ProvisioningSource(
            source_id=f"{profile.kind.value}-scim",
            tenant_id=tenant.id,
            base_url="https://iam.example.com/scim/v2",
        ),
        identity_service=identity_service,
        identity_repository=identities,
        tenancy_service=tenancy_service,
        membership_repository=memberships,
        resource_repository=InMemoryProvisioningUserRepository(),
        clock=clock,
        event_sink=events,
    )
    return ScimHttpTransport(
        provisioning,
        base_url="https://iam.example.com/scim/v2",
        provider_profile=profile,
    )


def _user_payload() -> dict[str, object]:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "userName": "alice@example.com",
        "externalId": "ext-42",
        "displayName": "Alice Example",
        "active": True,
    }


def test_provider_profiles_are_explicit_and_discoverable() -> None:
    assert scim_provider_profile("generic") is GENERIC_SCIM_PROFILE
    assert scim_provider_profile(ScimProviderKind.MICROSOFT_ENTRA) is MICROSOFT_ENTRA_PROFILE
    assert scim_provider_profile("okta") is OKTA_SCIM_PROFILE

    assert MICROSOFT_ENTRA_PROFILE.allow_unquoted_filter_values is True
    assert MICROSOFT_ENTRA_PROFILE.allow_and_filters is True
    assert MICROSOFT_ENTRA_PROFILE.preferred_user_lookup_attributes == (
        "externalId",
        "userName",
    )

    assert OKTA_SCIM_PROFILE.allow_unquoted_filter_values is False
    assert OKTA_SCIM_PROFILE.allow_and_filters is False
    assert OKTA_SCIM_PROFILE.preferred_user_lookup_attributes == ("userName",)
    assert OKTA_SCIM_PROFILE.default_page_size == 100
    assert OKTA_SCIM_PROFILE.supports_groups is False


def test_provider_profile_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="default_page_size"):
        ScimProviderProfile(
            kind=ScimProviderKind.GENERIC,
            allow_unquoted_filter_values=False,
            allow_and_filters=False,
            preferred_user_lookup_attributes=("userName",),
            default_page_size=0,
        )

    with pytest.raises(ValueError, match="must not be empty"):
        ScimProviderProfile(
            kind=ScimProviderKind.GENERIC,
            allow_unquoted_filter_values=False,
            allow_and_filters=False,
            preferred_user_lookup_attributes=(),
        )

    with pytest.raises(ValueError, match="Unsupported preferred"):
        ScimProviderProfile(
            kind=ScimProviderKind.GENERIC,
            allow_unquoted_filter_values=False,
            allow_and_filters=False,
            preferred_user_lookup_attributes=("displayName",),
        )


def test_original_generic_filter_contract_remains_strict() -> None:
    parsed = parse_user_filter('userName eq "alice@example.com"')
    assert parsed is not None
    assert parsed.attribute == "userName"
    assert parsed.value == "alice@example.com"

    with pytest.raises(InvalidScimRequest, match="requires quoted"):
        parse_user_filter("externalId eq ext-42")

    with pytest.raises(InvalidScimRequest, match="'and'"):
        parse_user_filter('userName eq "alice@example.com" and externalId eq "ext-42"')


def test_entra_profile_accepts_unquoted_and_conjoined_filters() -> None:
    expression = parse_user_filter_expression(
        'userName eq "alice@example.com" and externalId eq ext-42',
        profile=MICROSOFT_ENTRA_PROFILE,
    )

    assert expression is not None
    assert [(clause.attribute, clause.value) for clause in expression.clauses] == [
        ("userName", "alice@example.com"),
        ("externalId", "ext-42"),
    ]

    with_and_in_literal = parse_user_filter_expression(
        'userName eq "Research and Development"',
        profile=MICROSOFT_ENTRA_PROFILE,
    )
    assert with_and_in_literal is not None
    assert with_and_in_literal.clauses[0].value == "Research and Development"


def test_okta_profile_keeps_quoted_username_matching_behavior() -> None:
    quoted = parse_user_filter_expression(
        'Username Eq "alice@example.com"',
        profile=OKTA_SCIM_PROFILE,
    )
    assert quoted is not None
    assert quoted.clauses[0].attribute == "userName"

    with pytest.raises(InvalidScimRequest, match="requires quoted"):
        parse_user_filter_expression(
            "userName eq alice@example.com",
            profile=OKTA_SCIM_PROFILE,
        )


def test_entra_transport_matches_unquoted_external_id_and_and_filter() -> None:
    transport = _transport(MICROSOFT_ENTRA_PROFILE)
    created = transport.create_user(_user_payload())
    assert created.status == 201

    external = transport.list_users(filter_expression="externalId eq ext-42")
    assert external.status == 200
    assert external.body is not None
    assert external.body["totalResults"] == 1

    combined = transport.list_users(
        filter_expression='userName eq "ALICE@EXAMPLE.COM" and externalId eq ext-42'
    )
    assert combined.status == 200
    assert combined.body is not None
    assert combined.body["totalResults"] == 1

    mismatch = transport.list_users(
        filter_expression='userName eq "alice@example.com" and externalId eq wrong'
    )
    assert mismatch.status == 200
    assert mismatch.body is not None
    assert mismatch.body["totalResults"] == 0


def test_generic_and_okta_transports_do_not_inherit_entra_filter_quirks() -> None:
    for profile in (GENERIC_SCIM_PROFILE, OKTA_SCIM_PROFILE):
        transport = _transport(profile)
        transport.create_user(_user_payload())

        unquoted = transport.list_users(filter_expression="externalId eq ext-42")
        assert unquoted.status == 400
        assert unquoted.body is not None
        assert unquoted.body["scimType"] == "invalidFilter"

        conjoined = transport.list_users(
            filter_expression='userName eq "alice@example.com" and externalId eq "ext-42"'
        )
        assert conjoined.status == 400
        assert conjoined.body is not None
        assert conjoined.body["scimType"] == "invalidFilter"
