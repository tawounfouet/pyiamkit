"""Public reusable adapter conformance API."""

from .authentication import (
    AuthenticationConformance,
    AuthenticationProbe,
    SecretStoreConformance,
    SecretStoreProbe,
    TokenProviderConformance,
    TokenProviderProbe,
)
from .authorization import (
    AuthorizationConformance,
    AuthorizationProbe,
    TenantIsolationConformance,
    TenantIsolationProbe,
)
from .events import EventPublisherConformance, EventPublisherProbe
from .policy import PolicyEvaluatorConformance, PolicyEvaluatorProbe
from .report import ConformanceCheck, ConformanceFailure, ConformanceReport
from .repository import RepositoryConformance, RepositoryProbe

__all__ = [
    "AuthenticationConformance",
    "AuthenticationProbe",
    "AuthorizationConformance",
    "AuthorizationProbe",
    "ConformanceCheck",
    "ConformanceFailure",
    "ConformanceReport",
    "EventPublisherConformance",
    "EventPublisherProbe",
    "PolicyEvaluatorConformance",
    "PolicyEvaluatorProbe",
    "RepositoryConformance",
    "RepositoryProbe",
    "SecretStoreConformance",
    "SecretStoreProbe",
    "TenantIsolationConformance",
    "TenantIsolationProbe",
    "TokenProviderConformance",
    "TokenProviderProbe",
]
