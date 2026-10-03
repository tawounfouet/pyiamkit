"""Reusable conformance reporting primitives."""

from dataclasses import dataclass


class ConformanceFailure(AssertionError):
    """Raised when one or more adapter conformance checks fail."""


@dataclass(frozen=True, slots=True)
class ConformanceCheck:
    """One named conformance assertion."""

    name: str
    passed: bool
    detail: str | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("ConformanceCheck.name must not be empty")
        if self.passed and self.detail is not None:
            raise ValueError("Passing ConformanceCheck must not define detail")
        if not self.passed and (self.detail is None or not self.detail.strip()):
            raise ValueError("Failing ConformanceCheck requires detail")
        object.__setattr__(self, "name", name)


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """Deterministic result of one named suite against one adapter target."""

    suite: str
    target: str
    checks: tuple[ConformanceCheck, ...]

    def __post_init__(self) -> None:
        suite = self.suite.strip()
        target = self.target.strip()
        if not suite:
            raise ValueError("ConformanceReport.suite must not be empty")
        if not target:
            raise ValueError("ConformanceReport.target must not be empty")
        if not self.checks:
            raise ValueError("ConformanceReport.checks must not be empty")
        names = tuple(check.name for check in self.checks)
        if len(set(names)) != len(names):
            raise ValueError("ConformanceReport check names must be unique")
        object.__setattr__(self, "suite", suite)
        object.__setattr__(self, "target", target)

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[ConformanceCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def require_passed(self) -> None:
        if self.passed:
            return
        details = "; ".join(f"{check.name}: {check.detail}" for check in self.failures)
        raise ConformanceFailure(f"{self.suite} failed for {self.target}: {details}")
