"""Authorization constraints and Separation-of-Duties domain objects."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.identity import IdentityId
from pyiamkit.shared import EntityId
from pyiamkit.tenancy import TenantId

from .value_objects import PermissionCode, RoleId


class GovernanceRuleId(EntityId):
    """Stable identifier for an authorization governance rule."""


@dataclass(frozen=True, slots=True)
class ResourceDescriptor:
    """Framework-neutral protected resource presented to the authorization engine."""

    resource_type: str
    resource_id: str
    tenant_id: TenantId
    owner_id: IdentityId | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        resource_type = self.resource_type.strip().lower()
        resource_id = self.resource_id.strip()
        if not resource_type:
            raise ValueError("resource_type must not be empty")
        if not resource_id:
            raise ValueError("resource_id must not be empty")
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "resource_id", resource_id)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class NumericMaximumConstraint:
    """Deny when a numeric resource attribute exceeds a configured maximum."""

    id: GovernanceRuleId
    permission: PermissionCode
    resource_attribute: str
    maximum: Decimal
    tenant_id: TenantId | None = None

    def __post_init__(self) -> None:
        attribute = self.resource_attribute.strip()
        if not attribute:
            raise ValueError("resource_attribute must not be empty")
        object.__setattr__(self, "resource_attribute", attribute)


@dataclass(frozen=True, slots=True)
class ResourceAttributeEqualsConstraint:
    """Require a resource attribute to equal an expected textual value."""

    id: GovernanceRuleId
    permission: PermissionCode
    resource_attribute: str
    expected_value: str
    tenant_id: TenantId | None = None

    def __post_init__(self) -> None:
        attribute = self.resource_attribute.strip()
        if not attribute:
            raise ValueError("resource_attribute must not be empty")
        object.__setattr__(self, "resource_attribute", attribute)
        object.__setattr__(self, "expected_value", self.expected_value.strip())


@dataclass(frozen=True, slots=True)
class MinimumAssuranceConstraint:
    """Require minimum authentication assurance before a candidate RBAC allow."""

    id: GovernanceRuleId
    permission: PermissionCode
    minimum_assurance: AssuranceLevel
    require_mfa: bool = False
    tenant_id: TenantId | None = None


@dataclass(frozen=True, slots=True)
class MutuallyExclusiveRolesRule:
    """Static SoD rule forbidding two effective Roles on the same subject."""

    id: GovernanceRuleId
    name: str
    first_role_id: RoleId
    second_role_id: RoleId
    tenant_id: TenantId | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("SoD rule name must not be empty")
        if self.first_role_id == self.second_role_id:
            raise ValueError("Static SoD rule requires two distinct Roles")
        object.__setattr__(self, "name", name)


@dataclass(frozen=True, slots=True)
class DistinctActorSoDRule:
    """Dynamic SoD rule requiring subject != resource actor attribute."""

    id: GovernanceRuleId
    name: str
    permission: PermissionCode
    resource_attribute: str
    tenant_id: TenantId | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        attribute = self.resource_attribute.strip()
        if not name:
            raise ValueError("SoD rule name must not be empty")
        if not attribute:
            raise ValueError("resource_attribute must not be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "resource_attribute", attribute)


type AuthorizationConstraint = (
    NumericMaximumConstraint
    | ResourceAttributeEqualsConstraint
    | MinimumAssuranceConstraint
)
type SeparationOfDutyRule = MutuallyExclusiveRolesRule | DistinctActorSoDRule


class GovernanceViolationKind(StrEnum):
    AUTHENTICATION_CONTEXT_MISSING = "authentication_context_missing"
    ASSURANCE_STEP_UP_REQUIRED = "assurance_step_up_required"
    CONSTRAINT_CONTEXT_MISSING = "constraint_context_missing"
    CONSTRAINT_VIOLATION = "constraint_violation"
    SOD_CONTEXT_MISSING = "sod_context_missing"
    SOD_DYNAMIC_CONFLICT = "sod_dynamic_conflict"
    SOD_STATIC_CONFLICT = "sod_static_conflict"


@dataclass(frozen=True, slots=True)
class GovernanceViolation:
    kind: GovernanceViolationKind
    rule_id: GovernanceRuleId
    detail: str
    required_assurance_level: AssuranceLevel | None = None
    required_mfa: bool | None = None
