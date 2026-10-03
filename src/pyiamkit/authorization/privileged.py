"""Privileged-action security hooks for sensitive administration flows."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .domain.decision import AuthenticationEvidence
from .domain.errors import AuthorizationModelError
from .domain.value_objects import RoleId


class PrivilegedActionDenied(AuthorizationModelError):
    """Raised when a privileged administration action lacks required assurance."""

    code = "PRIVILEGED_ACTION_DENIED"


class PrivilegedAction(StrEnum):
    """Security-sensitive administration actions guarded by explicit policy."""

    SENSITIVE_ROLE_ASSIGNMENT = "sensitive_role_assignment"


@dataclass(frozen=True, slots=True)
class PrivilegedActionContext:
    """Authentication facts supplied to one privileged administration decision."""

    action: PrivilegedAction
    actor_id: IdentityId | None
    tenant_id: TenantId
    authentication: AuthenticationEvidence | None
    target_identity_id: IdentityId | None = None
    target_role_id: RoleId | None = None


class PrivilegedActionGuard(Protocol):
    """Framework-neutral policy hook for privileged administration actions."""

    def require(self, context: PrivilegedActionContext) -> None: ...


class MfaPrivilegedActionGuard:
    """Require an identified actor, MFA and minimum assurance for privileged actions."""

    def __init__(self, *, minimum_assurance: AssuranceLevel = AssuranceLevel.AAL2) -> None:
        self._minimum_assurance = minimum_assurance

    def require(self, context: PrivilegedActionContext) -> None:
        if context.actor_id is None:
            raise PrivilegedActionDenied("Privileged action requires an explicit actor")
        if (
            context.target_identity_id is not None
            and context.actor_id == context.target_identity_id
        ):
            raise PrivilegedActionDenied(
                "Sensitive role self-assignment requires a stronger approval guard"
            )

        evidence = context.authentication
        if evidence is None:
            raise PrivilegedActionDenied("Privileged action requires authentication evidence")
        if not evidence.mfa:
            raise PrivilegedActionDenied("Privileged action requires MFA")
        if _assurance_rank(evidence.assurance_level) < _assurance_rank(self._minimum_assurance):
            raise PrivilegedActionDenied(
                f"Privileged action requires assurance level {self._minimum_assurance.value}"
            )


def _assurance_rank(level: AssuranceLevel) -> int:
    return {
        AssuranceLevel.AAL1: 1,
        AssuranceLevel.AAL2: 2,
        AssuranceLevel.AAL3: 3,
    }[level]
