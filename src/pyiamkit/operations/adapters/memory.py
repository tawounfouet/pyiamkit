"""In-memory reference adapter for security-state version contracts."""

from datetime import datetime, timedelta
from threading import RLock

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from ..cache import AuthorizationCacheEntry, AuthorizationCacheKey
from ..ports import (
    AuthorizationCache,
    RevocationRegistry,
    SecurityStateReader,
    SecurityStateWriter,
)
from ..revocation import RevocationMarker, RevocationTargetType
from ..state import SecurityStateStamp, StateVersion

_ZERO = StateVersion(0)


class InMemorySecurityStateStore(SecurityStateReader, SecurityStateWriter):
    """Process-local reference implementation of security-state versions."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._runtime_generation = _ZERO
        self._identity: dict[IdentityId, StateVersion] = {}
        self._tenant: dict[TenantId, StateVersion] = {}
        self._membership: dict[tuple[IdentityId, TenantId], StateVersion] = {}
        self._subject_authorization: dict[tuple[IdentityId, TenantId], StateVersion] = {}
        self._tenant_authorization: dict[TenantId, StateVersion] = {}
        self._global_authorization = _ZERO
        self._governance: dict[TenantId, StateVersion] = {}
        self._authentication: dict[IdentityId, StateVersion] = {}

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp:
        with self._lock:
            subject_tenant = (identity_id, tenant_id)
            return SecurityStateStamp(
                runtime_generation=self._runtime_generation,
                identity=self._identity.get(identity_id, _ZERO),
                tenant=self._tenant.get(tenant_id, _ZERO),
                membership=self._membership.get(subject_tenant, _ZERO),
                subject_authorization=self._subject_authorization.get(subject_tenant, _ZERO),
                tenant_authorization=self._tenant_authorization.get(tenant_id, _ZERO),
                global_authorization=self._global_authorization,
                governance=self._governance.get(tenant_id, _ZERO),
                authentication=self._authentication.get(identity_id, _ZERO),
            )

    def bump_runtime_generation(self) -> StateVersion:
        with self._lock:
            self._runtime_generation = self._next(self._runtime_generation)
            return self._runtime_generation

    def bump_identity(self, identity_id: IdentityId) -> StateVersion:
        with self._lock:
            version = self._next(self._identity.get(identity_id))
            self._identity[identity_id] = version
            return version

    def bump_tenant(self, tenant_id: TenantId) -> StateVersion:
        with self._lock:
            version = self._next(self._tenant.get(tenant_id))
            self._tenant[tenant_id] = version
            return version

    def bump_membership(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion:
        with self._lock:
            key = (identity_id, tenant_id)
            version = self._next(self._membership.get(key))
            self._membership[key] = version
            return version

    def bump_subject_authorization(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion:
        with self._lock:
            key = (identity_id, tenant_id)
            version = self._next(self._subject_authorization.get(key))
            self._subject_authorization[key] = version
            return version

    def bump_tenant_authorization(self, tenant_id: TenantId) -> StateVersion:
        with self._lock:
            version = self._next(self._tenant_authorization.get(tenant_id))
            self._tenant_authorization[tenant_id] = version
            return version

    def bump_global_authorization(self) -> StateVersion:
        with self._lock:
            self._global_authorization = self._next(self._global_authorization)
            return self._global_authorization

    def bump_governance(self, tenant_id: TenantId) -> StateVersion:
        with self._lock:
            version = self._next(self._governance.get(tenant_id))
            self._governance[tenant_id] = version
            return version

    def bump_authentication(self, identity_id: IdentityId) -> StateVersion:
        with self._lock:
            version = self._next(self._authentication.get(identity_id))
            self._authentication[identity_id] = version
            return version

    @staticmethod
    def _next(current: StateVersion | None) -> StateVersion:
        value = 0 if current is None else current.value
        return StateVersion(value + 1)


class InMemoryAuthorizationCache(AuthorizationCache):
    """Thread-safe process-local authorization cache with exact stamp validation."""

    def __init__(self, *, cache_denials: bool = False) -> None:
        self._lock = RLock()
        self._cache_denials = cache_denials
        self._entries: dict[AuthorizationCacheKey, AuthorizationCacheEntry] = {}

    def get(
        self,
        key: AuthorizationCacheKey,
        *,
        current_state: SecurityStateStamp,
        at: datetime,
    ) -> AuthorizationCacheEntry | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if not entry.is_valid_for(current_state, at=at):
                self._entries.pop(key, None)
                return None
            return entry

    def put(self, entry: AuthorizationCacheEntry) -> None:
        if not self._cache_denials and not entry.decision.allowed:
            return
        with self._lock:
            self._entries[entry.key] = entry

    def delete(self, key: AuthorizationCacheKey) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class InMemoryRevocationRegistry(RevocationRegistry):
    """Thread-safe process-local deny-fast revocation registry."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._markers: dict[tuple[RevocationTargetType, str], RevocationMarker] = {}

    def record(self, marker: RevocationMarker) -> None:
        key = self._key(marker.target_type, marker.target_id)
        with self._lock:
            existing = self._markers.get(key)
            if existing is None or existing == marker:
                self._markers[key] = marker
                return
            if self._is_older(marker, existing):
                return
            if self._same_revision(marker, existing):
                raise ValueError(
                    "Conflicting revocation markers cannot share the same target revision"
                )
            self._markers[key] = marker

    def get(
        self,
        target_type: RevocationTargetType,
        target_id: str,
    ) -> RevocationMarker | None:
        key = self._key(target_type, target_id)
        with self._lock:
            return self._markers.get(key)

    def is_revoked(
        self,
        target_type: RevocationTargetType,
        target_id: str,
        *,
        at: datetime,
    ) -> bool:
        self._require_utc(at)
        marker = self.get(target_type, target_id)
        return marker is not None and marker.is_active(at=at)

    @staticmethod
    def _key(
        target_type: RevocationTargetType,
        target_id: str,
    ) -> tuple[RevocationTargetType, str]:
        if not isinstance(target_type, RevocationTargetType):
            raise TypeError("target_type must be a RevocationTargetType")
        if not isinstance(target_id, str):
            raise TypeError("target_id must be a string")
        normalized = target_id.strip()
        if not normalized:
            raise ValueError("target_id must not be empty")
        return target_type, normalized

    @staticmethod
    def _is_older(candidate: RevocationMarker, existing: RevocationMarker) -> bool:
        if candidate.source_version is not None and existing.source_version is not None:
            return candidate.source_version < existing.source_version
        return candidate.revoked_at < existing.revoked_at

    @staticmethod
    def _same_revision(candidate: RevocationMarker, existing: RevocationMarker) -> bool:
        if candidate.source_version is not None and existing.source_version is not None:
            return candidate.source_version == existing.source_version
        return candidate.revoked_at == existing.revoked_at

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("at must be UTC-aware")
