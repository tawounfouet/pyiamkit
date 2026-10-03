"""Targeted mutation gate for critical PyIAMKit security controls.

Each probe temporarily weakens one production guard, runs its sentinel test in a
fresh pytest process, and requires that the mutant is killed. The source file is
always restored before the next probe.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class MutationProbe:
    name: str
    path: str
    original: str
    mutant: str
    test_target: str


PROBES = (
    MutationProbe(
        name="scope_tenant_guard",
        path="src/pyiamkit/authorization/domain/decision.py",
        original=(
            "        if self.scope.tenant_id != self.tenant_id:\n"
            '            raise ValueError("AuthorizationRequest scope must belong to tenant_id.")\n'
        ),
        mutant=(
            "        if False and self.scope.tenant_id != self.tenant_id:\n"
            '            raise ValueError("AuthorizationRequest scope must belong to tenant_id.")\n'
        ),
        test_target=(
            "tests/security/test_authorization_properties.py::"
            "test_property_scope_mismatch_is_rejected_before_authorization"
        ),
    ),
    MutationProbe(
        name="inactive_subject_guard",
        path="src/pyiamkit/authorization/engine.py",
        original=(
            "        if identity.status is not IdentityStatus.ACTIVE:\n"
            "            return self._deny("
            "request, now, AuthorizationReason.DENY_SUBJECT_INACTIVE"
            ")\n"
        ),
        mutant=(
            "        if False and identity.status is not IdentityStatus.ACTIVE:\n"
            "            return self._deny(request, now, AuthorizationReason.DENY_SUBJECT_INACTIVE)\n"
        ),
        test_target=(
            "tests/security/test_authorization_properties.py::"
            "test_property_disabled_subject_never_authorizes"
        ),
    ),
    MutationProbe(
        name="dynamic_sod_guard",
        path="src/pyiamkit/authorization/engine.py",
        original="        if self._dynamic_sod is not None:\n",
        mutant="        if False and self._dynamic_sod is not None:\n",
        test_target="tests/unit/authorization/test_governance.py::test_dynamic_sod_blocks_self_approval",
    ),
    MutationProbe(
        name="revoked_session_guard",
        path="src/pyiamkit/authentication/domain/session.py",
        original=(
            "        return self.status is SessionStatus.ACTIVE and at < self.expires_at\n"
        ),
        mutant="        return at < self.expires_at\n",
        test_target=(
            "tests/unit/authentication/test_jwt.py::"
            "test_revoked_session_invalidates_previously_issued_token"
        ),
    ),
    MutationProbe(
        name="oidc_issuer_validation",
        path="src/pyiamkit/authentication/adapters/oidc.py",
        original="                issuer=self._issuer,\n",
        mutant="                issuer=None,\n",
        test_target=(
            "tests/unit/authentication/test_oidc.py::"
            "test_wrong_issuer_or_audience_is_rejected"
        ),
    ),
)


def run_probe(probe: MutationProbe) -> bool:
    path = ROOT / probe.path
    baseline = path.read_text(encoding="utf-8")
    count = baseline.count(probe.original)
    if count != 1:
        raise RuntimeError(
            f"{probe.name}: expected exactly one mutation target in {probe.path}, found {count}"
        )

    path.write_text(baseline.replace(probe.original, probe.mutant, 1), encoding="utf-8")
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", probe.test_target, "-q"],
            cwd=ROOT,
            check=False,
        )
    finally:
        path.write_text(baseline, encoding="utf-8")

    killed = completed.returncode != 0
    status = "KILLED" if killed else "SURVIVED"
    print(f"[{status}] {probe.name}: {probe.test_target}", flush=True)
    return killed


def main() -> int:
    survivors = [probe.name for probe in PROBES if not run_probe(probe)]
    if survivors:
        print("Security mutation survivors: " + ", ".join(survivors), file=sys.stderr)
        return 1
    print(f"All {len(PROBES)} targeted security mutants were killed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
