"""Invalidation value types for distributed IAM operations."""

from enum import StrEnum


class InvalidationKind(StrEnum):
    """Security-state dimensions that can invalidate derived runtime state."""

    IDENTITY = "identity"
    TENANT = "tenant"
    MEMBERSHIP = "membership"
    AUTHORIZATION = "authorization"
    GOVERNANCE = "governance"
    AUTHENTICATION = "authentication"
