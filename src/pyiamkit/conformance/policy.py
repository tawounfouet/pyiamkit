"""Reusable governance/policy evaluator conformance suite."""

from collections.abc import Callable
from dataclasses import dataclass

from pyiamkit.authorization import AuthorizationDecision, AuthorizationReason

from .report import ConformanceCheck, ConformanceReport


@dataclass(frozen=True, slots=True)
class PolicyEvaluatorProbe:
    """Governance scenarios used to qualify restrictive policy evaluation."""

    name: str
    matching_context: Callable[[], AuthorizationDecision]
    constraint_violation: Callable[[], AuthorizationDecision]
    missing_context: Callable[[], AuthorizationDecision]
    dynamic_sod_conflict: Callable[[], AuthorizationDecision]
    step_up_required: Callable[[], AuthorizationDecision]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("PolicyEvaluatorProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class PolicyEvaluatorConformance:
    """Qualify fail-closed governance semantics on top of an RBAC candidate allow."""

    suite_name = "PolicyEvaluatorConformance"

    def __init__(self, probe: PolicyEvaluatorProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check(
                    "matching_context_preserves_allow",
                    self._matching_context_preserves_allow,
                ),
                self._check(
                    "constraint_violation_reduces_access",
                    self._constraint_violation_reduces_access,
                ),
                self._check("missing_context_fails_closed", self._missing_context_fails_closed),
                self._check("dynamic_sod_conflict_denies", self._dynamic_sod_conflict_denies),
                self._check("insufficient_assurance_requires_step_up", self._step_up_required),
            ),
        )

    def _matching_context_preserves_allow(self) -> None:
        decision = self._probe.matching_context()
        if not decision.allowed:
            raise AssertionError(
                f"valid policy context was denied: {decision.reason_code.value}"
            )

    def _constraint_violation_reduces_access(self) -> None:
        self._require_reason(
            self._probe.constraint_violation(),
            AuthorizationReason.DENY_CONSTRAINT_VIOLATION,
        )

    def _missing_context_fails_closed(self) -> None:
        self._require_reason(
            self._probe.missing_context(),
            AuthorizationReason.DENY_CONSTRAINT_CONTEXT_MISSING,
        )

    def _dynamic_sod_conflict_denies(self) -> None:
        self._require_reason(
            self._probe.dynamic_sod_conflict(),
            AuthorizationReason.DENY_SOD_DYNAMIC_CONFLICT,
        )

    def _step_up_required(self) -> None:
        decision = self._probe.step_up_required()
        self._require_reason(decision, AuthorizationReason.DENY_STEP_UP_REQUIRED)
        if not decision.step_up_required:
            raise AssertionError("step-up denial is not marked as step_up_required")
        if decision.required_assurance_level is None:
            raise AssertionError("step-up denial omitted required assurance level")

    @staticmethod
    def _require_reason(
        decision: AuthorizationDecision,
        expected: AuthorizationReason,
    ) -> None:
        if decision.allowed:
            raise AssertionError(f"expected DENY {expected.value}, got ALLOW")
        if decision.reason_code is not expected:
            raise AssertionError(
                f"expected {expected.value}, got {decision.reason_code.value}"
            )

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)
