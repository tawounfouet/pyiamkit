"""SCIM-oriented provisioning orchestration."""

from dataclasses import dataclass
from datetime import datetime

from pyiamkit.identity import (
    IdentityApplicationService,
    IdentityRepository,
    IdentityStatus,
    User,
)
from pyiamkit.shared import Clock, DomainEvent, DomainEventSink
from pyiamkit.tenancy import (
    MembershipRepository,
    MembershipStatus,
    TenancyApplicationService,
    TenantId,
)

from .domain import (
    ProvisioningResourceId,
    ProvisioningResourceStatus,
    ProvisioningUser,
)
from .errors import (
    ProvisioningConflict,
    ProvisioningManagedStateConflict,
    ProvisioningPreconditionFailed,
    ProvisioningResourceNotFound,
)
from .ports import ProvisioningUserRepository
from .scim import (
    ScimEmail,
    ScimListResponse,
    ScimMeta,
    ScimPatchOperation,
    ScimUserInput,
    ScimUserResource,
    apply_user_patch,
    resource_location,
)


@dataclass(frozen=True, slots=True)
class ProvisioningSource:
    source_id: str
    tenant_id: TenantId
    base_url: str | None = None

    def __post_init__(self) -> None:
        source_id = self.source_id.strip()
        if not source_id:
            raise ValueError("source_id must not be empty")
        object.__setattr__(self, "source_id", source_id)
        if self.base_url is not None:
            base_url = self.base_url.strip()
            object.__setattr__(self, "base_url", base_url or None)


class ScimProvisioningService:
    """Provision SCIM Users into Identity + tenant Membership state."""

    def __init__(
        self,
        *,
        source: ProvisioningSource,
        identity_service: IdentityApplicationService,
        identity_repository: IdentityRepository,
        tenancy_service: TenancyApplicationService,
        membership_repository: MembershipRepository,
        resource_repository: ProvisioningUserRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._source = source
        self._identity_service = identity_service
        self._identities = identity_repository
        self._tenancy = tenancy_service
        self._memberships = membership_repository
        self._resources = resource_repository
        self._clock = clock
        self._events = event_sink

    def create_user(self, user: ScimUserInput) -> ScimUserResource:
        self._ensure_unique(user)

        identity = self._identity_service.create_user(
            display_name=user.effective_display_name,
            primary_email=user.primary_email,
            metadata={"provisioned_by": self._source.source_id},
        )
        identity = self._identity_service.activate_identity(identity.id)
        identity = self._identity_service.update_user_profile(
            identity.id,
            display_name=user.effective_display_name,
            primary_email=user.primary_email,
            first_name=user.name.given_name,
            last_name=user.name.family_name,
        )

        membership = self._tenancy.create_membership(
            identity_id=identity.id,
            tenant_id=self._source.tenant_id,
            source=f"scim:{self._source.source_id}",
        )
        membership = self._tenancy.activate_membership(membership.id)
        if not user.active:
            membership = self._tenancy.suspend_membership(membership.id)

        resource = ProvisioningUser.create(
            source_id=self._source.source_id,
            identity_id=identity.id,
            tenant_id=self._source.tenant_id,
            membership_id=membership.id,
            user_name=user.user_name,
            external_id=user.external_id,
            active=user.active,
            created_at=self._clock.now(),
        )
        self._resources.save(resource)
        self._publish("ScimUserProvisioned", resource)
        return self._render(resource)

    def get_user(self, resource_id: ProvisioningResourceId) -> ScimUserResource:
        return self._render(self._require_resource(resource_id))

    def find_by_external_id(self, external_id: str) -> ScimUserResource | None:
        resource = self._resources.find_by_external_id(
            self._source.source_id,
            external_id,
        )
        return None if resource is None else self._render(resource)

    def find_by_user_name(self, user_name: str) -> ScimUserResource | None:
        resource = self._resources.find_by_user_name(
            self._source.source_id,
            user_name,
        )
        return None if resource is None else self._render(resource)

    def list_users(
        self,
        *,
        start_index: int = 1,
        count: int = 100,
    ) -> ScimListResponse:
        if start_index < 1:
            raise ValueError("SCIM startIndex must be at least 1")
        if count < 0:
            raise ValueError("SCIM count must not be negative")
        resources = self._resources.list_for_source(
            self._source.source_id,
            self._source.tenant_id,
        )
        total = len(resources)
        start = start_index - 1
        page = resources[start : start + count]
        rendered = tuple(self._render(resource) for resource in page)
        return ScimListResponse(
            total_results=total,
            start_index=start_index,
            items_per_page=len(rendered),
            resources=rendered,
        )

    def replace_user(
        self,
        resource_id: ProvisioningResourceId,
        user: ScimUserInput,
        *,
        if_match: str | None = None,
    ) -> ScimUserResource:
        resource = self._require_resource(resource_id)
        self._require_match(resource, if_match)
        self._ensure_unique(user, current_id=resource.id)

        self._identity_service.update_user_profile(
            resource.identity_id,
            display_name=user.effective_display_name,
            primary_email=user.primary_email,
            first_name=user.name.given_name,
            last_name=user.name.family_name,
        )
        self._reconcile_membership(resource, active=user.active)
        resource.replace(
            user_name=user.user_name,
            external_id=user.external_id,
            active=user.active,
            at=self._clock.now(),
        )
        self._resources.save(resource)
        self._publish("ScimUserReplaced", resource)
        return self._render(resource)

    def patch_user(
        self,
        resource_id: ProvisioningResourceId,
        operations: tuple[ScimPatchOperation, ...],
        *,
        if_match: str | None = None,
    ) -> ScimUserResource:
        current = self.get_user(resource_id)
        desired = apply_user_patch(current.user, operations)
        result = self.replace_user(
            resource_id,
            desired,
            if_match=if_match,
        )
        self._publish("ScimUserPatched", self._require_resource(resource_id))
        return result

    def delete_user(
        self,
        resource_id: ProvisioningResourceId,
        *,
        if_match: str | None = None,
    ) -> None:
        resource = self._require_resource(resource_id)
        self._require_match(resource, if_match)

        membership = self._memberships.get(resource.membership_id)
        if membership is None:
            raise ProvisioningManagedStateConflict("Managed tenant Membership no longer exists")
        if membership.status in {
            MembershipStatus.PENDING,
            MembershipStatus.ACTIVE,
            MembershipStatus.SUSPENDED,
        }:
            self._tenancy.revoke_membership(membership.id)

        resource.delete(at=self._clock.now())
        self._resources.save(resource)
        self._publish("ScimUserDeleted", resource)

    def _reconcile_membership(self, resource: ProvisioningUser, *, active: bool) -> None:
        membership = self._memberships.get(resource.membership_id)
        if membership is None:
            raise ProvisioningManagedStateConflict("Managed tenant Membership no longer exists")

        if active:
            if membership.status is MembershipStatus.PENDING:
                self._tenancy.activate_membership(membership.id)
            elif membership.status is MembershipStatus.SUSPENDED:
                self._tenancy.reactivate_membership(membership.id)
            elif membership.status is not MembershipStatus.ACTIVE:
                raise ProvisioningManagedStateConflict(
                    f"Cannot reactivate Membership from {membership.status.value}"
                )
        else:
            if membership.status is MembershipStatus.PENDING:
                self._tenancy.activate_membership(membership.id)
                self._tenancy.suspend_membership(membership.id)
            elif membership.status is MembershipStatus.ACTIVE:
                self._tenancy.suspend_membership(membership.id)
            elif membership.status is not MembershipStatus.SUSPENDED:
                raise ProvisioningManagedStateConflict(
                    f"Cannot suspend Membership from {membership.status.value}"
                )

    def _ensure_unique(
        self,
        user: ScimUserInput,
        *,
        current_id: ProvisioningResourceId | None = None,
    ) -> None:
        by_name = self._resources.find_by_user_name(self._source.source_id, user.user_name)
        if by_name is not None and by_name.id != current_id:
            raise ProvisioningConflict(f"SCIM userName {user.user_name!r} already exists")
        if user.external_id is not None:
            by_external = self._resources.find_by_external_id(
                self._source.source_id,
                user.external_id,
            )
            if by_external is not None and by_external.id != current_id:
                raise ProvisioningConflict(
                    f"SCIM externalId {user.external_id!r} already exists for source"
                )

    def _require_resource(self, resource_id: ProvisioningResourceId) -> ProvisioningUser:
        resource = self._resources.get(resource_id)
        if resource is None or resource.status is ProvisioningResourceStatus.DELETED:
            raise ProvisioningResourceNotFound(resource_id)
        if (
            resource.source_id != self._source.source_id
            or resource.tenant_id != self._source.tenant_id
        ):
            raise ProvisioningResourceNotFound(resource_id)
        return resource

    @staticmethod
    def _require_match(resource: ProvisioningUser, if_match: str | None) -> None:
        if if_match is None or if_match.strip() == "*":
            return
        if if_match.strip() != resource.etag:
            raise ProvisioningPreconditionFailed(
                f"SCIM resource version mismatch: expected {resource.etag}"
            )

    def _render(self, resource: ProvisioningUser) -> ScimUserResource:
        identity = self._identities.get(resource.identity_id)
        if identity is None:
            raise ProvisioningManagedStateConflict("Managed Identity no longer exists")
        if not isinstance(identity.profile, User):
            raise ProvisioningManagedStateConflict("Managed Identity is not a User")

        email = identity.profile.primary_email
        emails = () if email is None else (ScimEmail(str(email), primary=True),)
        user = ScimUserInput(
            user_name=resource.user_name,
            display_name=identity.display_name,
            external_id=resource.external_id,
            active=resource.active,
            name=self._scim_name(identity.profile.first_name, identity.profile.last_name),
            emails=emails,
        )
        return ScimUserResource(
            id=str(resource.id),
            user=user,
            meta=ScimMeta(
                resource_type="User",
                created=resource.created_at,
                last_modified=resource.updated_at,
                version=resource.etag,
                location=resource_location(self._source.base_url, str(resource.id)),
            ),
        )

    @staticmethod
    def _scim_name(first_name: str | None, last_name: str | None):
        from .scim import ScimName

        return ScimName(given_name=first_name, family_name=last_name)

    def _publish(self, event_type: str, resource: ProvisioningUser) -> None:
        self._events.publish(
            (
                DomainEvent(
                    event_type=event_type,
                    occurred_at=self._clock.now(),
                    metadata={
                        "resource_id": str(resource.id),
                        "identity_id": str(resource.identity_id),
                        "tenant_id": str(resource.tenant_id),
                        "source_id": resource.source_id,
                        "version": resource.version,
                    },
                ),
            )
        )
