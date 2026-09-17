"""Database-like in-memory implementation of IdentityRepository."""

from ...domain.aggregates.identity import Identity
from ...domain.value_objects.identity_id import IdentityId


class InMemoryIdentityRepository:
    def __init__(self) -> None:
        self._items: dict[IdentityId, Identity] = {}

    def get(self, identity_id: IdentityId) -> Identity | None:
        identity = self._items.get(identity_id)
        return None if identity is None else self._clone(identity)

    def save(self, identity: Identity) -> None:
        self._items[identity.id] = self._clone(identity)

    def exists(self, identity_id: IdentityId) -> bool:
        return identity_id in self._items

    def find_by_external_subject(
        self,
        provider_id: str,
        external_subject: str,
    ) -> Identity | None:
        provider = provider_id.strip()
        subject = external_subject.strip()
        for identity in self._items.values():
            if any(
                link.provider_id == provider and link.external_subject == subject
                for link in identity.external_links
            ):
                return self._clone(identity)
        return None

    @staticmethod
    def _clone(identity: Identity) -> Identity:
        return Identity._rehydrate(
            identity_id=identity.id,
            version=identity.version,
            identity_type=identity.type,
            status=identity.status,
            display_name=identity.display_name,
            profile=identity.profile,
            created_at=identity.created_at,
            updated_at=identity.updated_at,
            activated_at=identity.activated_at,
            suspended_at=identity.suspended_at,
            disabled_at=identity.disabled_at,
            archived_at=identity.archived_at,
            external_links=identity.external_links,
            metadata=identity.metadata,
        )
