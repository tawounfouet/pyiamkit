"""Revocation value types for distributed IAM operations."""

from enum import StrEnum


class RevocationTargetType(StrEnum):
    """Security-sensitive target categories that can be revoked."""

    SESSION = "session"
    IDENTITY = "identity"
    MEMBERSHIP = "membership"
    ROLE_BINDING = "role_binding"
    TENANT = "tenant"
