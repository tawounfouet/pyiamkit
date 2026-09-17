"""Minimal post-build smoke test."""

from importlib.metadata import version

import pyiamkit

if __name__ == "__main__":
    distribution_version = version("pyiamkit")
    if pyiamkit.__version__ != distribution_version:
        raise SystemExit(
            "PyIAMKit runtime/distribution version mismatch: "
            f"{pyiamkit.__version__} != {distribution_version}"
        )
    print(f"PyIAMKit {pyiamkit.__version__} import OK")
