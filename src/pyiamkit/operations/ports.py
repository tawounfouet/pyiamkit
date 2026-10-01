"""Ports for authoritative security-state version reads and mutations."""

from datetime import datetime
from typing import Protocol

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .cache import AuthorizationCacheEntry, AuthorizationCacheKey
from .invalidation import InvalidationEvent
from .revocation import RevocationMarker, RevocationTargetType
from .state import SecurityStateStamp, StateVersion


class SecurityStateReader(Protocol):
    """Read the current security-state stamp for one subject and tenant."""

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp: ...


class SecurityStateWriter(Protocol):
    """Advance authoritative security-state versions after security mutations."""

    def bump_runtime_generation(self) -> StateVersion: ...

    def bump_identity(self, identity_id: IdentityId) -> StateVersion: ...

    def bump_tenant(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_membership(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion: ...

    def bump_subject_authorization(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> StateVersion: ...

    def bump_tenant_authorization(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_global_authorization(self) -> StateVersion: ...

    def bump_governance(self, tenant_id: TenantId) -> StateVersion: ...

    def bump_authentication(self, identity_id: IdentityId) -> StateVersion: ...


class AuthorizationCache(Protocol):
    """Derived authorization cache validated against authoritative security state."""

    def get(
        self,
        key: AuthorizationCacheKey,
        *,
        current_state: SecurityStateStamp,
        at: datetime,
    ) -> AuthorizationCacheEntry | None: ...

    def put(self, entry: AuthorizationCacheEntry) -> None: ...

    def delete(self, key: AuthorizationCacheKey) -> None: ...

    def clear(self) -> None: ...


class RevocationRegistry(Protocol):
    """Distributed deny-fast overlay that never replaces authoritative state."""

    def record(self, marker: RevocationMarker) -> None: ...

    def get(
        self,
        target_type: RevocationTargetType,
        target_id: str,
    ) -> RevocationMarker | None: ...

    def is_revoked(
        self,
        target_type: RevocationTargetType,
        target_id: str,
        *,
        at: datetime,
    ) -> bool: ...



class SecurityStateProjection(Protocol):
    """Non-authoritative distributed projection of complete security-state stamps."""

    def get(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp | None: ...

    def project(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
        stamp: SecurityStateStamp,
    ) -> None: ...


class InvalidationPublisher(Protocol):
    """Publish low-latency invalidation signals without becoming state authority."""

    def publish(self, event: InvalidationEvent) -> None: ...


class InvalidationHandler(Protocol):
    """Consume one decoded invalidation event idempotently."""

    def handle(self, event: InvalidationEvent) -> bool: ...
