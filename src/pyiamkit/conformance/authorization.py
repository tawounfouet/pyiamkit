"""Reusable authorization and tenant-isolation conformance suites."""

from collections.abc import Callable
from dataclasses import dataclass

from pyiamkit.authorization import AuthorizationDecision, AuthorizationReason

from .report import ConformanceCheck, ConformanceReport


@dataclass(frozen=True, slots=True)
class AuthorizationProbe:
    """Scenario callbacks used to qualify an authorization implementation."""

    name: str
    allowed: Callable[[], AuthorizationDecision]
    no_active_binding: Callable[[], AuthorizationDecision]
    unregistered_permission: Callable[[], AuthorizationDecision]
    inactive_subject: Callable[[], AuthorizationDecision]
    revoked_access: Callable[[], AuthorizationDecision]
    repeat_same_request: Callable[[], tuple[AuthorizationDecision, AuthorizationDecision]]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("AuthorizationProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class AuthorizationConformance:
    """Qualify stable default-deny authorization semantics."""

    suite_name = "AuthorizationConformance"

    def __init__(self, probe: AuthorizationProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("matching_grant_allows", self._matching_grant_allows),
                self._check("no_binding_denies", self._no_binding_denies),
                self._check(
                    "unregistered_permission_denies",
                    self._unregistered_permission_denies,
                ),
                self._check("inactive_subject_denies", self._inactive_subject_denies),
                self._check("revoked_access_denies", self._revoked_access_denies),
                self._check(
                    "same_context_is_semantically_deterministic",
                    self._same_context_is_semantically_deterministic,
                ),
            ),
        )

    def _matching_grant_allows(self) -> None:
        decision = self._probe.allowed()
        if not decision.allowed:
            raise AssertionError(f"expected ALLOW, got {decision.reason_code.value}")
        if decision.reason_code not in {
            AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH,
            AuthorizationReason.ALLOW_INHERITED_ROLE_PERMISSION_MATCH,
        }:
            raise AssertionError(f"unexpected ALLOW reason: {decision.reason_code.value}")

    def _no_binding_denies(self) -> None:
        self._require_reason(
            self._probe.no_active_binding(),
            AuthorizationReason.DENY_NO_ACTIVE_BINDING,
        )

    def _unregistered_permission_denies(self) -> None:
        self._require_reason(
            self._probe.unregistered_permission(),
            AuthorizationReason.DENY_PERMISSION_NOT_REGISTERED,
        )

    def _inactive_subject_denies(self) -> None:
        self._require_reason(
            self._probe.inactive_subject(),
            AuthorizationReason.DENY_SUBJECT_INACTIVE,
        )

    def _revoked_access_denies(self) -> None:
        self._require_reason(
            self._probe.revoked_access(),
            AuthorizationReason.DENY_NO_ACTIVE_BINDING,
        )

    def _same_context_is_semantically_deterministic(self) -> None:
        first, second = self._probe.repeat_same_request()
        first_projection = (
            first.result,
            first.reason_code,
            first.subject_id,
            first.tenant_id,
            first.permission,
            first.scope,
            first.valid_until,
            first.matched_membership_id,
            first.bound_role_id,
            first.matched_binding_id,
            first.matched_role_id,
            first.matched_rule_id,
            first.required_assurance_level,
            first.required_mfa,
            first.resource,
            first.correlation_id,
            first.explanation_path,
        )
        second_projection = (
            second.result,
            second.reason_code,
            second.subject_id,
            second.tenant_id,
            second.permission,
            second.scope,
            second.valid_until,
            second.matched_membership_id,
            second.bound_role_id,
            second.matched_binding_id,
            second.matched_role_id,
            second.matched_rule_id,
            second.required_assurance_level,
            second.required_mfa,
            second.resource,
            second.correlation_id,
            second.explanation_path,
        )
        if first_projection != second_projection:
            raise AssertionError("same authorization context produced different semantics")

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


@dataclass(frozen=True, slots=True)
class TenantIsolationProbe:
    """Cross-Tenant scenarios used to qualify isolation boundaries."""

    name: str
    same_tenant: Callable[[], AuthorizationDecision]
    cross_tenant_without_binding: Callable[[], AuthorizationDecision]
    foreign_tenant_role: Callable[[], AuthorizationDecision]
    construct_scope_mismatch: Callable[[], None]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("TenantIsolationProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class TenantIsolationConformance:
    """Qualify that authorization state never leaks across Tenant boundaries."""

    suite_name = "TenantIsolationConformance"

    def __init__(self, probe: TenantIsolationProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("same_tenant_control_allows", self._same_tenant_control_allows),
                self._check(
                    "cross_tenant_binding_does_not_leak",
                    self._cross_tenant_binding_does_not_leak,
                ),
                self._check(
                    "foreign_tenant_role_fails_closed",
                    self._foreign_tenant_role_fails_closed,
                ),
                self._check(
                    "scope_tenant_mismatch_rejected",
                    self._scope_tenant_mismatch_rejected,
                ),
            ),
        )

    def _same_tenant_control_allows(self) -> None:
        decision = self._probe.same_tenant()
        if not decision.allowed:
            raise AssertionError(
                f"same-Tenant control request was denied: {decision.reason_code.value}"
            )

    def _cross_tenant_binding_does_not_leak(self) -> None:
        decision = self._probe.cross_tenant_without_binding()
        if decision.allowed:
            raise AssertionError("Tenant A binding authorized a Tenant B request")
        if decision.reason_code is not AuthorizationReason.DENY_NO_ACTIVE_BINDING:
            raise AssertionError(
                "cross-Tenant request did not fail at the binding boundary: "
                f"{decision.reason_code.value}"
            )

    def _foreign_tenant_role_fails_closed(self) -> None:
        decision = self._probe.foreign_tenant_role()
        if decision.allowed:
            raise AssertionError("foreign-Tenant Role authorized the request")
        if decision.reason_code is not AuthorizationReason.DENY_ROLE_TENANT_MISMATCH:
            raise AssertionError(
                "foreign-Tenant Role did not produce tenant-mismatch denial: "
                f"{decision.reason_code.value}"
            )

    def _scope_tenant_mismatch_rejected(self) -> None:
        try:
            self._probe.construct_scope_mismatch()
        except ValueError:
            return
        raise AssertionError("scope/Tenant mismatch was accepted")

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
