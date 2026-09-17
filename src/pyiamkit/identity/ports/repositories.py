"""Identity repository port."""

from typing import Protocol

from ..domain.aggregates.identity import Identity
from ..domain.value_objects.identity_id import IdentityId


class IdentityRepository(Protocol):
    def get(self, identity_id: IdentityId) -> Identity | None:
        ...

    def save(self, identity: Identity) -> None:
        ...

    def exists(self, identity_id: IdentityId) -> bool:
        ...

    def find_by_external_subject(
        self,
        provider_id: str,
        external_subject: str,
    ) -> Identity | None:
        ...
