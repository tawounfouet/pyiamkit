"""Security-state version primitives for distributed IAM operations."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class StateVersion:
    """Immutable monotonic version value used for security-sensitive state."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("StateVersion.value must be an integer")
        if self.value < 0:
            raise ValueError("StateVersion.value must be greater than or equal to zero")


@dataclass(frozen=True, slots=True)
class SecurityStateStamp:
    """Version vector covering state that can affect an authorization decision."""

    identity: StateVersion
    tenant: StateVersion
    membership: StateVersion
    authorization: StateVersion
    governance: StateVersion
    authentication: StateVersion

    def __post_init__(self) -> None:
        for name, value in (
            ("identity", self.identity),
            ("tenant", self.tenant),
            ("membership", self.membership),
            ("authorization", self.authorization),
            ("governance", self.governance),
            ("authentication", self.authentication),
        ):
            if not isinstance(value, StateVersion):
                raise TypeError(f"SecurityStateStamp.{name} must be a StateVersion")
