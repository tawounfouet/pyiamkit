from uuid import UUID

import pytest

from pyiamkit.identity import EmailAddress, IdentityId
from pyiamkit.identity.domain.exceptions import InvalidEmailAddress


def test_identity_id_is_specialized_uuid_identifier() -> None:
    identity_id = IdentityId.new()

    assert isinstance(identity_id.value, UUID)
    assert IdentityId.parse(str(identity_id)) == identity_id


def test_email_address_normalizes_domain() -> None:
    email = EmailAddress.parse(" Alice@Example.COM ")

    assert str(email) == "Alice@example.com"


@pytest.mark.parametrize("value", ["", "alice", "@example.com", "a@b", "a b@example.com"])
def test_email_address_rejects_invalid_values(value: str) -> None:
    with pytest.raises(InvalidEmailAddress):
        EmailAddress.parse(value)
