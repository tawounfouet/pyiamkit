"""Official authorization model adapters."""

from .memory import InMemoryPermissionCatalogRepository, InMemoryRoleRepository

__all__ = ["InMemoryPermissionCatalogRepository", "InMemoryRoleRepository"]
