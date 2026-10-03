import hashlib
import json
from pathlib import Path

from scripts.generate_release_evidence import generate_release_evidence


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
    checksums, sbom_path, provenance_path = generate_release_evidence(
        pyproject_path=pyproject,
        dist_dir=dist,
        output_dir=output,
        commit_sha="abc123",
        workflow="Production Qualification",
        run_id="42",
        builder="pytest",
    )

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
    assert provenance["source"]["commit"] == "abc123"
    assert provenance["build"]["workflow"] == "Production Qualification"
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

    try:
        generate_release_evidence(
            pyproject_path=pyproject,
            dist_dir=dist,
            output_dir=tmp_path / "evidence",
            commit_sha="abc123",
            workflow="Production Qualification",
            run_id="42",
            builder="pytest",
        )
    except ValueError as exc:
        assert "sdist" in str(exc)
    else:
        raise AssertionError("missing sdist did not fail release evidence generation")
