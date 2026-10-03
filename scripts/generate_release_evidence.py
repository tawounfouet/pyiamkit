"""Generate release evidence for PyIAMKit build artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_project(pyproject_path: Path) -> dict[str, Any]:
    with pyproject_path.open("rb") as stream:
        data = tomllib.load(stream)
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml does not contain [project]")
    return project


def _dependency_component(requirement: str, *, group: str) -> dict[str, Any]:
    match = _REQUIREMENT_NAME.match(requirement.strip())
    if match is None:
        raise ValueError(f"Cannot parse dependency requirement: {requirement!r}")
    return {
        "type": "library",
        "name": match.group(1),
        "properties": [
            {"name": "pyiamkit.requirement", "value": requirement},
            {"name": "pyiamkit.dependency-group", "value": group},
        ],
    }


def generate_release_evidence(
    *,
    pyproject_path: Path,
    dist_dir: Path,
    output_dir: Path,
    commit_sha: str,
    workflow: str,
    run_id: str,
    builder: str,
) -> tuple[Path, Path, Path]:
    project = _load_project(pyproject_path)
    name = str(project["name"])
    version = str(project["version"])

    artifacts = sorted(
        path
        for path in dist_dir.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    if not any(path.suffix == ".whl" for path in artifacts):
        raise ValueError("release evidence requires a wheel artifact")
    if not any(path.name.endswith(".tar.gz") for path in artifacts):
        raise ValueError("release evidence requires an sdist artifact")

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_records = [
        {
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in artifacts
    ]

    checksums_path = output_dir / "SHA256SUMS"
    checksums_path.write_text(
        "".join(f"{item['sha256']}  {item['name']}\n" for item in artifact_records),
        encoding="utf-8",
    )

    components: list[dict[str, Any]] = []
    dependencies = project.get("dependencies", [])
    if isinstance(dependencies, list):
        components.extend(
            _dependency_component(str(requirement), group="core") for requirement in dependencies
        )

    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in sorted(optional):
            requirements = optional[group]
            if isinstance(requirements, list):
                components.extend(
                    _dependency_component(str(requirement), group=str(group))
                    for requirement in requirements
                )

    timestamp = datetime.now(UTC).isoformat()
    package_ref = f"pkg:pypi/{name}@{version}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{package_ref}:{commit_sha}")

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "library",
                "bom-ref": package_ref,
                "name": name,
                "version": version,
                "purl": package_ref,
            },
            "properties": [
                {"name": "pyiamkit.commit", "value": commit_sha},
                {"name": "pyiamkit.builder", "value": builder},
            ],
        },
        "components": components,
    }
    sbom_path = output_dir / "sbom.cdx.json"
    sbom_path.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    provenance = {
        "schema_version": 1,
        "package": {"name": name, "version": version},
        "source": {"commit": commit_sha},
        "build": {
            "workflow": workflow,
            "run_id": run_id,
            "builder": builder,
            "timestamp": timestamp,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "artifacts": artifact_records,
    }
    provenance_path = output_dir / "provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return checksums_path, sbom_path, provenance_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output-dir", type=Path, default=Path("release-evidence"))
    args = parser.parse_args()

    generate_release_evidence(
        pyproject_path=args.pyproject,
        dist_dir=args.dist_dir,
        output_dir=args.output_dir,
        commit_sha=os.getenv("GITHUB_SHA", "local"),
        workflow=os.getenv("GITHUB_WORKFLOW", "local"),
        run_id=os.getenv("GITHUB_RUN_ID", "local"),
        builder=os.getenv("RUNNER_NAME", "local"),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
