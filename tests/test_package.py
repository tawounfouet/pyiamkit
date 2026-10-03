import pyiamkit


def test_package_exposes_version() -> None:
    assert pyiamkit.__version__ == "0.5.0a2"
