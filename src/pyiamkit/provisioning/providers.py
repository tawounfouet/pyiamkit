"""SCIM provider interoperability profiles."""

from dataclasses import dataclass
from enum import StrEnum


class ScimProviderKind(StrEnum):
    GENERIC = "generic"
    MICROSOFT_ENTRA = "microsoft_entra"
    OKTA = "okta"


class ScimDeprovisionMode(StrEnum):
    ACTIVE_FALSE = "active_false"


@dataclass(frozen=True, slots=True)
class ScimProviderProfile:
    """Compatibility hints for one SCIM client family.

    Profiles never grant authorization and never change PyIAMKit lifecycle
    invariants. They only tune protocol parsing and interoperability defaults.
    """

    kind: ScimProviderKind
    allow_unquoted_filter_values: bool
    allow_and_filters: bool
    preferred_user_lookup_attributes: tuple[str, ...]
    default_page_size: int = 100
    deprovision_mode: ScimDeprovisionMode = ScimDeprovisionMode.ACTIVE_FALSE
    supports_groups: bool = False

    def __post_init__(self) -> None:
        if self.default_page_size < 1:
            raise ValueError("default_page_size must be at least 1")
        if not self.preferred_user_lookup_attributes:
            raise ValueError("preferred_user_lookup_attributes must not be empty")
        unsupported = {
            attribute
            for attribute in self.preferred_user_lookup_attributes
            if attribute not in {"userName", "externalId"}
        }
        if unsupported:
            raise ValueError(
                "Unsupported preferred user lookup attributes: " + ", ".join(sorted(unsupported))
            )


GENERIC_SCIM_PROFILE = ScimProviderProfile(
    kind=ScimProviderKind.GENERIC,
    allow_unquoted_filter_values=False,
    allow_and_filters=False,
    preferred_user_lookup_attributes=("userName", "externalId"),
    supports_groups=True,
)

MICROSOFT_ENTRA_PROFILE = ScimProviderProfile(
    kind=ScimProviderKind.MICROSOFT_ENTRA,
    allow_unquoted_filter_values=True,
    allow_and_filters=True,
    preferred_user_lookup_attributes=("externalId", "userName"),
    supports_groups=True,
)

OKTA_SCIM_PROFILE = ScimProviderProfile(
    kind=ScimProviderKind.OKTA,
    allow_unquoted_filter_values=False,
    allow_and_filters=False,
    preferred_user_lookup_attributes=("userName",),
    supports_groups=True,
)


def scim_provider_profile(kind: ScimProviderKind | str) -> ScimProviderProfile:
    parsed = kind if isinstance(kind, ScimProviderKind) else ScimProviderKind(kind)
    if parsed is ScimProviderKind.MICROSOFT_ENTRA:
        return MICROSOFT_ENTRA_PROFILE
    if parsed is ScimProviderKind.OKTA:
        return OKTA_SCIM_PROFILE
    return GENERIC_SCIM_PROFILE
