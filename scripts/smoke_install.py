"""Minimal post-build smoke test."""

import pyiamkit


if __name__ == "__main__":
    if not pyiamkit.__version__:
        raise SystemExit("PyIAMKit version is missing")
    print(f"PyIAMKit {pyiamkit.__version__} import OK")
