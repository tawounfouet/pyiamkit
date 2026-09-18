"""Reference adapters for the Authentication bounded context."""

from .memory import InMemoryCredentialRepository, InMemorySessionRepository

__all__ = ["InMemoryCredentialRepository", "InMemorySessionRepository"]
