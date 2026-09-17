from uuid import UUID

import pytest

from pyiamkit.shared import EntityId


def test_entity_id_new_generates_uuid() -> None:
    entity_id = EntityId.new()

    assert isinstance(entity_id.value, UUID)


def test_entity_id_round_trips_through_string() -> None:
    entity_id = EntityId.new()

    assert EntityId.parse(str(entity_id)) == entity_id


def test_entity_id_parse_rejects_invalid_uuid() -> None:
    with pytest.raises(ValueError):
        EntityId.parse("not-a-uuid")
