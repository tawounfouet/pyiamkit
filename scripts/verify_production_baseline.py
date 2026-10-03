"""Verify the static production qualification and stable-release baseline."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

API_FREEZE_FILES = (
    Path("docs/api/public-api-freeze-1.0.0rc1.json"),
    Path("docs/api/public-api-freeze-1.0.0rc1.md"),
    Path("docs/api/compatibility-policy-1.0.md"),
    Path("docs/api/error-reason-permission-contracts-1.0.md"),
    Path("docs/api/adapter-contract-matrix-1.0.0rc1.md"),
    Path("scripts/public_api_contract.py"),
    Path(".github/workflows/api-compatibility.yml"),
)

REQUIRED_FILES = (
    Path("CHANGELOG.md"),
    Path("PUBLIC_API.md"),
    Path("README.md"),
    Path("SECURITY.md"),
    Path("docs/architecture/production-qualification-0.5.0rc1.md"),
    Path("docs/architecture/threat-model-delta-0.5.0rc1.md"),
    Path("docs/architecture/production-stable-0.5.0.md"),
    Path("docs/guides/production-deployment.md"),
    Path("docs/guides/security-operations.md"),
    Path("docs/guides/persistence-migration-and-rollback.md"),
    Path("docs/guides/integrations.md"),
    Path("docs/guides/production-checklist.md"),
    Path("src/pyiamkit/persistence/sqlalchemy/migrations.py"),
    Path("tests/qualification/test_schema_migrations.py"),
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/security.yml"),
    Path(".github/workflows/production-qualification.yml"),
)

_VERSION_PATTERN = re.compile(r'__version__\s*=\s*"([^"]+)"')


def _project_version(root: Path) -> str:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        raise ValueError("missing pyproject.toml")
    with pyproject_path.open("rb") as stream:
        project = tomllib.load(stream).get("project", {})
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("pyproject.toml is missing project.version")
    return version.strip()


def verify_baseline(root: Path) -> tuple[str, ...]:
    failures: list[str] = []

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            failures.append(f"missing required file: {relative}")

    try:
        expected_version = _project_version(root)
    except ValueError as exc:
        failures.append(str(exc))
        return tuple(failures)

    if expected_version.startswith("1."):
        for relative in API_FREEZE_FILES:
            if not (root / relative).is_file():
                failures.append(f"missing 1.x API-freeze file: {relative}")

    version_path = root / "src/pyiamkit/_version.py"
    if not version_path.is_file():
        failures.append("missing src/pyiamkit/_version.py")
    else:
        match = _VERSION_PATTERN.search(version_path.read_text(encoding="utf-8"))
        runtime_version = match.group(1) if match else None
        if runtime_version != expected_version:
            failures.append(
                f"runtime version mismatch: expected {expected_version}, got {runtime_version!r}"
            )

    required_mentions = {
        "CHANGELOG.md": f"## [{expected_version}]",
        "PUBLIC_API.md": f"## {expected_version}\n",
        "README.md": "0.5.0      First production-oriented stable",
        "docs/architecture/production-qualification-0.5.0rc1.md": (
            "CI\nSecurity\nProduction Qualification"
        ),
        "docs/architecture/threat-model-delta-0.5.0rc1.md": (
            "No new critical risk is intentionally accepted"
        ),
        "docs/architecture/production-stable-0.5.0.md": (
            "first production-oriented stable release"
        ),
        "docs/guides/persistence-migration-and-rollback.md": ("0001_0_5_0rc1_baseline"),
        "docs/guides/production-deployment.md": "controlled production deployments",
        "docs/guides/security-operations.md": "default deny",
        "docs/guides/integrations.md": "Third-party adapters",
        "docs/guides/production-checklist.md": "Production checklist",
    }

    for relative, needle in required_mentions.items():
        path = root / relative
        if path.is_file() and needle not in path.read_text(encoding="utf-8"):
            failures.append(f"{relative} is missing required baseline text: {needle!r}")

    if expected_version.startswith("1."):
        api_required_mentions = {
            "docs/api/public-api-freeze-1.0.0rc1.md": "27 documented public namespaces",
            "docs/api/compatibility-policy-1.0.md": "minimum transition window",
            "docs/api/error-reason-permission-contracts-1.0.md": "AuthorizationReason",
            "docs/api/adapter-contract-matrix-1.0.0rc1.md": "RepositoryConformance",
        }
        for relative, needle in api_required_mentions.items():
            path = root / relative
            if path.is_file() and needle not in path.read_text(encoding="utf-8"):
                failures.append(f"{relative} is missing required API-freeze text: {needle!r}")

    public_api = root / "PUBLIC_API.md"
    if public_api.is_file() and "migrate_schema()" not in public_api.read_text(encoding="utf-8"):
        failures.append("PUBLIC_API.md is missing the production migration API")

    return tuple(failures)


def main() -> int:
    try:
        expected_version = _project_version(Path("."))
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1

    failures = verify_baseline(Path("."))
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1

    print(f"Production baseline verified for PyIAMKit {expected_version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
