import pytest

from pyiamkit.authorization import InvalidPermissionCode, Permission, PermissionCode


def test_permission_code_is_canonical_and_decomposable() -> None:
    code = PermissionCode(" Invoice.Approve ")
    assert str(code) == "invoice.approve"
    assert code.resource == "invoice"
    assert code.action == "approve"


def test_namespaced_permission_code_is_supported() -> None:
    code = PermissionCode("iam.role.assign")
    assert code.resource == "iam.role"
    assert code.action == "assign"


@pytest.mark.parametrize("value", ["", "read", ".read", "invoice.", "invoice.*", "Invoice Read"])
def test_invalid_permission_codes_are_rejected(value: str) -> None:
    with pytest.raises(InvalidPermissionCode):
        PermissionCode(value)


def test_permission_is_immutable_catalog_entry() -> None:
    permission = Permission(PermissionCode("audit.read"), " Read audit ", sensitive=True)
    assert permission.description == "Read audit"
    assert permission.sensitive is True
