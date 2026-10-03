"""Reusable repository adapter conformance suite."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from .report import ConformanceCheck, ConformanceReport

EntityT = TypeVar("EntityT")
KeyT = TypeVar("KeyT")


@dataclass(frozen=True, slots=True)
class RepositoryProbe(Generic[EntityT, KeyT]):
    """Adapter-specific callbacks consumed by RepositoryConformance.

    A probe should be backed by a fresh repository instance. The snapshot callback
    must return an immutable or equality-comparable representation of persisted state.
    """

    name: str
    create: Callable[[], EntityT]
    identifier: Callable[[EntityT], KeyT]
    missing_identifier: Callable[[], KeyT]
    save: Callable[[EntityT], None]
    get: Callable[[KeyT], EntityT | None]
    snapshot: Callable[[EntityT], object]
    mutate: Callable[[EntityT], None] | None = None
    exists: Callable[[KeyT], bool] | None = None
    after_load: Callable[[EntityT], None] | None = None
    require_copy_semantics: bool = True

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("RepositoryProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class RepositoryConformance(Generic[EntityT, KeyT]):
    """Qualify baseline persistence semantics shared by PyIAMKit repositories."""

    suite_name = "RepositoryConformance"

    def __init__(self, probe: RepositoryProbe[EntityT, KeyT]) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        checks = [
            self._check("missing_read_returns_none", self._missing_read_returns_none),
            self._check("round_trip_preserves_state", self._round_trip_preserves_state),
        ]
        if self._probe.require_copy_semantics:
            checks.append(self._check("round_trip_returns_copy", self._round_trip_returns_copy))
        if self._probe.exists is not None:
            checks.append(self._check("exists_tracks_persistence", self._exists_tracks_persistence))
        if self._probe.mutate is not None:
            checks.extend(
                (
                    self._check("save_is_snapshot_isolated", self._save_is_snapshot_isolated),
                    self._check(
                        "loaded_value_is_snapshot_isolated",
                        self._loaded_value_is_snapshot_isolated,
                    ),
                )
            )
        if self._probe.after_load is not None:
            checks.append(self._check("rehydration_invariant", self._rehydration_invariant))

        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=tuple(checks),
        )

    def _missing_read_returns_none(self) -> None:
        missing = self._probe.missing_identifier()
        if self._probe.get(missing) is not None:
            raise AssertionError("missing identifier returned a persisted entity")

    def _round_trip_preserves_state(self) -> None:
        entity = self._probe.create()
        key = self._probe.identifier(entity)
        expected = self._probe.snapshot(entity)
        self._probe.save(entity)
        loaded = self._require_loaded(key)
        if self._probe.snapshot(loaded) != expected:
            raise AssertionError("round-trip changed persisted state")

    def _round_trip_returns_copy(self) -> None:
        entity = self._probe.create()
        key = self._probe.identifier(entity)
        self._probe.save(entity)
        loaded = self._require_loaded(key)
        if loaded is entity:
            raise AssertionError("repository returned the caller-owned entity instance")

    def _exists_tracks_persistence(self) -> None:
        exists = self._probe.exists
        if exists is None:
            raise AssertionError("exists callback is unavailable")
        missing = self._probe.missing_identifier()
        if exists(missing):
            raise AssertionError("exists returned true for a missing identifier")

        entity = self._probe.create()
        key = self._probe.identifier(entity)
        self._probe.save(entity)
        if not exists(key):
            raise AssertionError("exists returned false for a persisted identifier")

    def _save_is_snapshot_isolated(self) -> None:
        mutate = self._probe.mutate
        if mutate is None:
            raise AssertionError("mutate callback is unavailable")

        entity = self._probe.create()
        key = self._probe.identifier(entity)
        expected = self._probe.snapshot(entity)
        self._probe.save(entity)
        mutate(entity)

        loaded = self._require_loaded(key)
        if self._probe.snapshot(loaded) != expected:
            raise AssertionError("caller mutation changed already-persisted state")

    def _loaded_value_is_snapshot_isolated(self) -> None:
        mutate = self._probe.mutate
        if mutate is None:
            raise AssertionError("mutate callback is unavailable")

        entity = self._probe.create()
        key = self._probe.identifier(entity)
        expected = self._probe.snapshot(entity)
        self._probe.save(entity)

        loaded = self._require_loaded(key)
        mutate(loaded)
        loaded_again = self._require_loaded(key)
        if self._probe.snapshot(loaded_again) != expected:
            raise AssertionError("mutation of loaded entity changed repository state")

    def _rehydration_invariant(self) -> None:
        after_load = self._probe.after_load
        if after_load is None:
            raise AssertionError("after_load callback is unavailable")

        entity = self._probe.create()
        key = self._probe.identifier(entity)
        self._probe.save(entity)
        after_load(self._require_loaded(key))

    def _require_loaded(self, key: KeyT) -> EntityT:
        loaded = self._probe.get(key)
        if loaded is None:
            raise AssertionError("persisted entity could not be loaded")
        return loaded

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)
