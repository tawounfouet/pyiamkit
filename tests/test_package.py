import pyiamkit


def test_package_exposes_version() -> None:
    assert pyiamkit.__version__ == "1.0.0"
