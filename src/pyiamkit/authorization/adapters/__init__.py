"""Official authorization model adapters."""

from .memory import (
    InMemoryPermissionCatalogRepository,
    InMemoryRoleBindingRepository,
    InMemoryRoleRepository,
)

__all__ = [
    "InMemoryPermissionCatalogRepository",
    "InMemoryRoleBindingRepository",
    "InMemoryRoleRepository",
]
