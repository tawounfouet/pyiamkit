"""Opaque Redis key construction for operational adapters."""

import hashlib
from dataclasses import dataclass

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .cache import AuthorizationCacheKey, CacheNamespace
from .revocation import RevocationTargetType


@dataclass(frozen=True, slots=True)
class RedisKeyspace:
    """Versioned Redis names without raw security-target identifiers."""

    namespace: CacheNamespace

    def authorization_cache(self, key: AuthorizationCacheKey) -> str:
        if not isinstance(key, AuthorizationCacheKey):
            raise TypeError("key must be an AuthorizationCacheKey")
        return f"{self.namespace.prefix}:authz:{key.digest}"

    @property
    def authorization_cache_pattern(self) -> str:
        return f"{self.namespace.prefix}:authz:*"

    def revocation(self, target_type: RevocationTargetType, target_id: str) -> str:
        if not isinstance(target_type, RevocationTargetType):
            raise TypeError("target_type must be a RevocationTargetType")
        return (
            f"{self.namespace.prefix}:revocation:{target_type.value}:"
            f"{self._opaque(target_type.value, target_id)}"
        )

    def security_state(self, identity_id: IdentityId, tenant_id: TenantId) -> str:
        if not isinstance(identity_id, IdentityId):
            raise TypeError("identity_id must be an IdentityId")
        if not isinstance(tenant_id, TenantId):
            raise TypeError("tenant_id must be a TenantId")
        subject = self._opaque("identity", str(identity_id))
        tenant = self._opaque("tenant", str(tenant_id))
        return f"{self.namespace.prefix}:state:{subject}:{tenant}"

    @property
    def security_state_pattern(self) -> str:
        return f"{self.namespace.prefix}:state:*"

    @property
    def invalidation_channel(self) -> str:
        return f"{self.namespace.prefix}:invalidation"

    @staticmethod
    def _opaque(label: str, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("Redis key identifiers must be strings")
        normalized = value.strip()
        if not normalized:
            raise ValueError("Redis key identifiers must not be empty")
        material = f"{label}\x00{normalized}".encode()
        return hashlib.sha256(material).hexdigest()
