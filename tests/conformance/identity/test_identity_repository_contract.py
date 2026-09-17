from datetime import UTC, datetime

from pyiamkit.identity import Identity
from pyiamkit.identity.adapters.memory import InMemoryIdentityRepository

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_in_memory_repository_save_get_and_exists() -> None:
    repository = InMemoryIdentityRepository()
    identity = Identity.create_user(display_name="Alice", created_at=NOW)

    repository.save(identity)

    assert repository.exists(identity.id)
    loaded = repository.get(identity.id)
    assert loaded == identity
    assert loaded is not identity


def test_in_memory_repository_has_database_like_copy_semantics() -> None:
    repository = InMemoryIdentityRepository()
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    repository.save(identity)

    identity.activate(at=NOW)
    loaded = repository.get(identity.id)

    assert loaded is not None
    assert loaded.status.value == "pending"
    loaded.activate(at=NOW)
    loaded_again = repository.get(identity.id)
    assert loaded_again is not None
    assert loaded_again.status.value == "pending"


def test_in_memory_repository_rehydration_emits_no_events() -> None:
    repository = InMemoryIdentityRepository()
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    repository.save(identity)

    loaded = repository.get(identity.id)

    assert loaded is not None
    assert loaded.pull_events() == ()


def test_in_memory_repository_finds_external_subject() -> None:
    repository = InMemoryIdentityRepository()
    identity = Identity.create_user(display_name="Alice", created_at=NOW)
    identity.link_external_identity(
        provider_id="entra",
        external_subject="subject-1",
        at=NOW,
    )
    repository.save(identity)

    found = repository.find_by_external_subject(" entra ", " subject-1 ")

    assert found is not None
    assert found.id == identity.id
    assert repository.find_by_external_subject("entra", "unknown") is None
