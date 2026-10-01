"""Translate domain mutations into authoritative security-state version changes."""

from collections.abc import Sequence
from datetime import UTC

from pyiamkit.identity import IdentityId
from pyiamkit.shared import DomainEvent, DomainEventSink
from pyiamkit.tenancy import TenantId

from .errors import RevocationRegistryUnavailable
from .invalidation import InvalidationEvent, InvalidationKind
from .ports import InvalidationPublisher, RevocationRegistry, SecurityStateWriter
from .revocation import RevocationMarker, RevocationTargetType
from .state import StateVersion

_IDENTITY_STATE_EVENTS = frozenset(
    {
        "IdentityCreated",
        "IdentityActivated",
        "IdentitySuspended",
        "IdentityReactivated",
        "IdentityDisabled",
        "IdentityArchived",
    }
)
_IDENTITY_AUTHENTICATION_EVENTS = frozenset(
    {
        "ExternalIdentityLinked",
        "ExternalIdentityUnlinked",
    }
)
_TENANT_EVENTS = frozenset(
    {
        "TenantCreated",
        "TenantActivated",
        "TenantSuspended",
        "TenantReactivated",
        "TenantDisabled",
        "TenantArchived",
    }
)
_MEMBERSHIP_EVENTS = frozenset(
    {
        "MembershipCreated",
        "MembershipActivated",
        "MembershipSuspended",
        "MembershipReactivated",
        "MembershipExpired",
        "MembershipRevoked",
    }
)
_ROLE_BINDING_EVENTS = frozenset(
    {
        "RoleAssigned",
        "RoleBindingExpired",
        "RoleBindingReactivated",
        "RoleBindingRevoked",
        "RoleBindingSuspended",
    }
)
_ROLE_EVENTS = frozenset(
    {
        "RoleCreated",
        "RoleDisabled",
        "RoleParentAdded",
        "RoleParentRemoved",
        "RolePermissionAdded",
        "RolePermissionRemoved",
        "RoleSensitivityChanged",
        "RoleAssignabilityChanged",
    }
)
_GLOBAL_AUTHORIZATION_EVENTS = frozenset({"PermissionRegistered"})
_GOVERNANCE_EVENTS = frozenset(
    {
        "AuthorizationConstraintRegistered",
        "MinimumAssuranceConstraintRegistered",
        "StaticSoDRuleRegistered",
        "DynamicSoDRuleRegistered",
    }
)
_AUTHENTICATION_EVENTS = frozenset(
    {
        "CredentialCreated",
        "CredentialRevoked",
        "CredentialExpired",
        "SessionOpened",
        "SessionRevoked",
        "SessionExpired",
        "SessionSteppedUp",
        "MfaFactorCreated",
        "MfaFactorActivated",
        "MfaFactorVerified",
        "MfaFactorRevoked",
    }
)


class SecurityStateMutationEventSink(DomainEventSink):
    """Decorate domain-event publication with security-state invalidation hooks."""

    def __init__(
        self,
        downstream: DomainEventSink,
        *,
        state_writer: SecurityStateWriter,
        invalidation_publisher: InvalidationPublisher | None = None,
        revocations: RevocationRegistry | None = None,
    ) -> None:
        self._downstream = downstream
        self._state_writer = state_writer
        self._invalidation_publisher = invalidation_publisher
        self._revocations = revocations

    def publish(self, events: Sequence[DomainEvent]) -> None:
        materialized = tuple(events)
        invalidations = tuple(
            invalidation
            for event in materialized
            if (invalidation := self._apply(event)) is not None
        )
        self._downstream.publish(materialized)
        if self._invalidation_publisher is not None:
            for invalidation in invalidations:
                self._invalidation_publisher.publish(invalidation)

    def _apply(self, event: DomainEvent) -> InvalidationEvent | None:
        if event.event_type in _IDENTITY_STATE_EVENTS:
            identity_id = self._identity_id(event)
            version = self._state_writer.bump_identity(identity_id)
            if event.event_type in {"IdentitySuspended", "IdentityDisabled", "IdentityArchived"}:
                self._record_revocation(
                    event,
                    target_type=RevocationTargetType.IDENTITY,
                    target_id=str(identity_id),
                    version=version,
                )
            return self._invalidation(
                event,
                kind=InvalidationKind.IDENTITY,
                target_id=str(identity_id),
                version=version,
            )

        if event.event_type in _IDENTITY_AUTHENTICATION_EVENTS:
            identity_id = self._identity_id(event)
            version = self._state_writer.bump_authentication(identity_id)
            return self._invalidation(
                event,
                kind=InvalidationKind.AUTHENTICATION,
                target_id=str(identity_id),
                version=version,
            )

        if event.event_type in _TENANT_EVENTS:
            tenant_id = self._tenant_id(event)
            version = self._state_writer.bump_tenant(tenant_id)
            if event.event_type in {"TenantSuspended", "TenantDisabled", "TenantArchived"}:
                self._record_revocation(
                    event,
                    target_type=RevocationTargetType.TENANT,
                    target_id=str(tenant_id),
                    tenant_id=tenant_id,
                    version=version,
                )
            return self._invalidation(
                event,
                kind=InvalidationKind.TENANT,
                target_id=str(tenant_id),
                tenant_id=tenant_id,
                version=version,
            )

        if event.event_type in _MEMBERSHIP_EVENTS:
            identity_id = self._identity_id(event)
            tenant_id = self._tenant_id(event)
            version = self._state_writer.bump_membership(identity_id, tenant_id)
            if event.event_type in {
                "MembershipSuspended",
                "MembershipRevoked",
                "MembershipExpired",
            }:
                self._record_revocation(
                    event,
                    target_type=RevocationTargetType.MEMBERSHIP,
                    target_id=self._required_text(event, "membership_id"),
                    tenant_id=tenant_id,
                    version=version,
                )
            return self._invalidation(
                event,
                kind=InvalidationKind.MEMBERSHIP,
                target_id=str(identity_id),
                tenant_id=tenant_id,
                version=version,
            )

        if event.event_type in _ROLE_BINDING_EVENTS:
            identity_id = self._identity_id(event)
            tenant_id = self._tenant_id(event)
            version = self._state_writer.bump_subject_authorization(identity_id, tenant_id)
            if event.event_type in {
                "RoleBindingSuspended",
                "RoleBindingRevoked",
                "RoleBindingExpired",
            }:
                self._record_revocation(
                    event,
                    target_type=RevocationTargetType.ROLE_BINDING,
                    target_id=self._required_text(event, "binding_id"),
                    tenant_id=tenant_id,
                    version=version,
                )
            return self._invalidation(
                event,
                kind=InvalidationKind.AUTHORIZATION,
                target_id=str(identity_id),
                tenant_id=tenant_id,
                version=version,
            )

        if event.event_type in _ROLE_EVENTS:
            tenant_id = self._optional_tenant_id(event)
            if tenant_id is None:
                version = self._state_writer.bump_global_authorization()
                target_id = "global"
            else:
                version = self._state_writer.bump_tenant_authorization(tenant_id)
                target_id = str(tenant_id)
            return self._invalidation(
                event,
                kind=InvalidationKind.AUTHORIZATION,
                target_id=target_id,
                tenant_id=tenant_id,
                version=version,
            )

        if event.event_type in _GLOBAL_AUTHORIZATION_EVENTS:
            version = self._state_writer.bump_global_authorization()
            return self._invalidation(
                event,
                kind=InvalidationKind.AUTHORIZATION,
                target_id="global",
                version=version,
            )

        if event.event_type in _GOVERNANCE_EVENTS:
            tenant_id = self._optional_tenant_id(event)
            if tenant_id is None:
                version = self._state_writer.bump_runtime_generation()
                target_id = "global"
            else:
                version = self._state_writer.bump_governance(tenant_id)
                target_id = str(tenant_id)
            return self._invalidation(
                event,
                kind=InvalidationKind.GOVERNANCE,
                target_id=target_id,
                tenant_id=tenant_id,
                version=version,
            )

        if event.event_type in _AUTHENTICATION_EVENTS:
            identity_id = self._identity_id(event)
            version = self._state_writer.bump_authentication(identity_id)
            return self._invalidation(
                event,
                kind=InvalidationKind.AUTHENTICATION,
                target_id=str(identity_id),
                version=version,
            )

        return None

    @staticmethod
    def _identity_id(event: DomainEvent) -> IdentityId:
        raw = SecurityStateMutationEventSink._required_text(event, "identity_id")
        return IdentityId.parse(raw)

    @staticmethod
    def _tenant_id(event: DomainEvent) -> TenantId:
        raw = SecurityStateMutationEventSink._required_text(event, "tenant_id")
        return TenantId.parse(raw)

    @staticmethod
    def _optional_tenant_id(event: DomainEvent) -> TenantId | None:
        raw = event.metadata.get("tenant_id")
        if raw is None:
            return None
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(
                f"{event.event_type} metadata tenant_id must be a non-empty string or null"
            )
        return TenantId.parse(raw)

    @staticmethod
    def _required_text(event: DomainEvent, key: str) -> str:
        raw = event.metadata.get(key)
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(
                f"{event.event_type} metadata {key} must be a non-empty string"
            )
        return raw

    def _record_revocation(
        self,
        event: DomainEvent,
        *,
        target_type: RevocationTargetType,
        target_id: str,
        version: StateVersion,
        tenant_id: TenantId | None = None,
    ) -> None:
        if self._revocations is None:
            return
        try:
            self._revocations.record(
                RevocationMarker(
                    target_type=target_type,
                    target_id=target_id,
                    revoked_at=event.occurred_at.astimezone(UTC),
                    reason_code=event.event_type,
                    tenant_id=tenant_id,
                    source_version=version,
                )
            )
        except RevocationRegistryUnavailable:
            return

    @staticmethod
    def _invalidation(
        event: DomainEvent,
        *,
        kind: InvalidationKind,
        target_id: str,
        version: StateVersion,
        tenant_id: TenantId | None = None,
    ) -> InvalidationEvent:
        return InvalidationEvent(
            event_id=event.event_id,
            kind=kind,
            target_id=target_id,
            tenant_id=tenant_id,
            state_version=version,
            occurred_at=event.occurred_at.astimezone(UTC),
        )
