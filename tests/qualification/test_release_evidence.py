import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _run_generator(
    *,
    pyproject: Path,
    dist: Path,
    output: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/generate_release_evidence.py",
            "--pyproject",
            str(pyproject),
            "--dist-dir",
            str(dist),
            "--output-dir",
            str(output),
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def test_release_evidence_contains_artifact_hashes_sbom_and_provenance(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "pyiamkit"
version = "0.5.0rc1"
dependencies = []

[project.optional-dependencies]
jwt = ["PyJWT[crypto]>=2.14,<3"]
sqlalchemy = ["sqlalchemy>=2,<3"]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "pyiamkit-0.5.0rc1-py3-none-any.whl"
    sdist = dist / "pyiamkit-0.5.0rc1.tar.gz"
    wheel.write_bytes(b"wheel-bytes")
    sdist.write_bytes(b"sdist-bytes")

    output = tmp_path / "release-evidence"
    _run_generator(pyproject=pyproject, dist=dist, output=output)

    checksums = output / "SHA256SUMS"
    sbom_path = output / "sbom.cdx.json"
    provenance_path = output / "provenance.json"

    expected_wheel_hash = hashlib.sha256(b"wheel-bytes").hexdigest()
    expected_sdist_hash = hashlib.sha256(b"sdist-bytes").hexdigest()
    checksum_text = checksums.read_text(encoding="utf-8")
    assert f"{expected_wheel_hash}  {wheel.name}" in checksum_text
    assert f"{expected_sdist_hash}  {sdist.name}" in checksum_text

    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "pyiamkit"
    assert sbom["metadata"]["component"]["version"] == "0.5.0rc1"
    assert {component["name"] for component in sbom["components"]} == {
        "PyJWT",
        "sqlalchemy",
    }

    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance["package"] == {"name": "pyiamkit", "version": "0.5.0rc1"}
    assert provenance["source"]["commit"] == "local"
    assert provenance["build"]["workflow"] == "local"
    assert {item["name"] for item in provenance["artifacts"]} == {
        wheel.name,
        sdist.name,
    }


def test_release_evidence_requires_wheel_and_sdist(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "pyiamkit"\nversion = "0.5.0rc1"\n',
        encoding="utf-8",
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "pyiamkit-0.5.0rc1-py3-none-any.whl").write_bytes(b"wheel")

    result = _run_generator(
        pyproject=pyproject,
        dist=dist,
        output=tmp_path / "evidence",
        check=False,
    )

    assert result.returncode != 0
    assert "sdist" in result.stderr
