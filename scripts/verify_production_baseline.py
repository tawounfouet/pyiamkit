"""Verify the static production-qualification release baseline."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

EXPECTED_VERSION = "0.5.0rc1"

REQUIRED_FILES = (
    Path("CHANGELOG.md"),
    Path("PUBLIC_API.md"),
    Path("README.md"),
    Path("SECURITY.md"),
    Path("docs/architecture/production-qualification-0.5.0rc1.md"),
    Path("docs/architecture/threat-model-delta-0.5.0rc1.md"),
    Path("docs/guides/persistence-migration-and-rollback.md"),
    Path("src/pyiamkit/persistence/sqlalchemy/migrations.py"),
    Path("tests/qualification/test_schema_migrations.py"),
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/security.yml"),
    Path(".github/workflows/production-qualification.yml"),
)

_VERSION_PATTERN = re.compile(r'__version__\s*=\s*"([^"]+)"')


def verify_baseline(root: Path) -> tuple[str, ...]:
    failures: list[str] = []

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            failures.append(f"missing required file: {relative}")

    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file():
        failures.append("missing pyproject.toml")
        return tuple(failures)

    with pyproject_path.open("rb") as stream:
        pyproject = tomllib.load(stream)

    project = pyproject.get("project", {})
    version = project.get("version")
    if version != EXPECTED_VERSION:
        failures.append(f"pyproject version mismatch: expected {EXPECTED_VERSION}, got {version!r}")

    version_path = root / "src/pyiamkit/_version.py"
    if not version_path.is_file():
        failures.append("missing src/pyiamkit/_version.py")
    else:
        match = _VERSION_PATTERN.search(version_path.read_text(encoding="utf-8"))
        runtime_version = match.group(1) if match else None
        if runtime_version != EXPECTED_VERSION:
            failures.append(
                f"runtime version mismatch: expected {EXPECTED_VERSION}, got {runtime_version!r}"
            )

    required_mentions = {
        "CHANGELOG.md": "## [0.5.0rc1]",
        "PUBLIC_API.md": "## 0.5.0rc1",
        "README.md": "0.5.0rc1   Production qualification",
        "docs/architecture/production-qualification-0.5.0rc1.md": (
            "CI\nSecurity\nProduction Qualification"
        ),
        "docs/architecture/threat-model-delta-0.5.0rc1.md": (
            "No new critical risk is intentionally accepted"
        ),
        "docs/guides/persistence-migration-and-rollback.md": ("0001_0_5_0rc1_baseline"),
    }

    for relative, needle in required_mentions.items():
        path = root / relative
        if path.is_file() and needle not in path.read_text(encoding="utf-8"):
            failures.append(f"{relative} is missing required baseline text: {needle!r}")

    public_api = root / "PUBLIC_API.md"
    if public_api.is_file() and "migrate_schema()" not in public_api.read_text(encoding="utf-8"):
        failures.append("PUBLIC_API.md is missing the RC1 migration API")

    return tuple(failures)


def main() -> int:
    failures = verify_baseline(Path("."))
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1

    print(f"Production baseline verified for PyIAMKit {EXPECTED_VERSION}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
