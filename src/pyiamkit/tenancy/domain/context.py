"""Tenant-isolation helpers."""

from .errors import TenantMismatch
from .value_objects import TenantId


class TenantIsolationGuard:
    @staticmethod
    def ensure_same_tenant(expected: TenantId, actual: TenantId) -> None:
        if expected != actual:
            raise TenantMismatch(expected, actual)
