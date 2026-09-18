import os
from datetime import UTC, datetime, timedelta

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Credential,
    CredentialType,
    MfaFactor,
    MfaFactorId,
    MfaFactorType,
    Session,
)
from pyiamkit.authorization import (
    AuthenticationEvidence,
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    GovernanceRuleId,
    MinimumAssuranceConstraint,
    Permission,
    PermissionCode,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.identity import Identity
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyAuditRepository,
    SqlAlchemyConstraintRepository,
    SqlAlchemyCredentialRepository,
    SqlAlchemyIdentityRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyMfaFactorRepository,
    SqlAlchemyPermissionCatalogRepository,
    SqlAlchemyProvisioningUserRepository,
    SqlAlchemyRoleBindingRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyTenantRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
    drop_schema,
)
from pyiamkit.provisioning import ProvisioningUser
from pyiamkit.shared import Clock
from pyiamkit.tenancy import Membership, Tenant, TenantScope

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


@pytest.mark.integration
def test_postgresql_end_to_end_authorization_persistence() -> None:
    database_url = os.getenv("PYIAMKIT_TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("PYIAMKIT_TEST_DATABASE_URL is not configured")

    engine = create_sqlalchemy_engine(database_url)
    drop_schema(engine)
    create_schema(engine)
    factory = create_session_factory(engine)

    with factory.begin() as session:
        identities = SqlAlchemyIdentityRepository(session)
        constraints = SqlAlchemyConstraintRepository(session)
        credentials = SqlAlchemyCredentialRepository(session)
        sessions = SqlAlchemySessionRepository(session)
        tenants = SqlAlchemyTenantRepository(session)
        memberships = SqlAlchemyMembershipRepository(session)
        factors = SqlAlchemyMfaFactorRepository(session)
        permissions = SqlAlchemyPermissionCatalogRepository(session)
        provisioning = SqlAlchemyProvisioningUserRepository(session)
        roles = SqlAlchemyRoleRepository(session)
        bindings = SqlAlchemyRoleBindingRepository(session)
        audit = SqlAlchemyAuditRepository(session)

        identity = Identity.create_user(display_name="Alice", created_at=NOW)
        identity.pull_events()
        identity.activate(at=NOW)
        identity.pull_events()
        identities.save(identity)

        credential = Credential.create(
            identity_id=identity.id,
            credential_type=CredentialType.PASSKEY,
            reference="vault://credentials/alice-passkey",
            fingerprint="sha256:postgres",
            created_at=NOW,
        )
        credential.pull_events()
        credentials.save(credential)

        factor = MfaFactor.create(
            factor_id=MfaFactorId.new(),
            identity_id=identity.id,
            factor_type=MfaFactorType.TOTP,
            secret_reference="vault://mfa/postgres/alice",
            label="CI Authenticator",
            created_at=NOW,
        )
        factor.pull_events()
        factor.activate(at=NOW + timedelta(seconds=30), counter=42)
        factor.pull_events()
        factors.save(factor)

        auth_session = Session.open(
            identity_id=identity.id,
            context=AuthenticationContext(
                method=AuthenticationMethod.PASSWORD,
                assurance_level=AssuranceLevel.AAL1,
                mfa=False,
                authenticated_at=NOW,
                device_id="postgres-ci",
            ),
            created_at=NOW,
            expires_at=NOW + timedelta(hours=8),
        )
        auth_session.pull_events()
        auth_session.step_up(
            assurance_level=AssuranceLevel.AAL2,
            factor_id=factor.id,
            at=NOW + timedelta(minutes=1),
        )
        auth_session.pull_events()
        sessions.save(auth_session)

        tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
        tenant.pull_events()
        tenant.activate(at=NOW)
        tenant.pull_events()
        tenants.save(tenant)

        membership = Membership.create(
            identity_id=identity.id,
            tenant_id=tenant.id,
            created_at=NOW,
        )
        membership.pull_events()
        membership.activate(at=NOW)
        membership.pull_events()
        memberships.save(membership)

        provisioning_user = ProvisioningUser.create(
            source_id="postgres-scim",
            identity_id=identity.id,
            tenant_id=tenant.id,
            membership_id=membership.id,
            user_name="alice@example.com",
            external_id="postgres-ext-42",
            active=True,
            created_at=NOW,
        )
        provisioning.save(provisioning_user)

        permission = Permission(PermissionCode("invoice.read"), "Read invoices")
        permissions.save(permission)
        role = Role.create(
            name="Reader",
            role_type=RoleType.TENANT,
            tenant_id=tenant.id,
            created_at=NOW,
        )
        role.pull_events()
        role.add_permission(permission.code, at=NOW)
        role.pull_events()
        roles.save(role)

        binding = RoleBinding.create(
            identity_id=identity.id,
            role_id=role.id,
            tenant_id=tenant.id,
            scope=TenantScope(tenant.id),
            created_at=NOW,
        )
        binding.pull_events()
        bindings.save(binding)

        assurance_rule = MinimumAssuranceConstraint(
            id=GovernanceRuleId.new(),
            permission=permission.code,
            minimum_assurance=AssuranceLevel.AAL2,
            require_mfa=True,
            tenant_id=tenant.id,
        )
        constraints.save(assurance_rule)

        engine_service = AuthorizationEngine(
            identity_repository=identities,
            tenant_repository=tenants,
            membership_repository=memberships,
            permission_repository=permissions,
            role_repository=roles,
            binding_repository=bindings,
            constraint_repository=constraints,
            audit_sink=audit,
            clock=FrozenClock(),
        )
        decision = engine_service.authorize(
            AuthorizationRequest(
                subject_id=identity.id,
                tenant_id=tenant.id,
                permission=permission.code,
                scope=TenantScope(tenant.id),
                authentication=AuthenticationEvidence(
                    assurance_level=auth_session.context.assurance_level,
                    mfa=auth_session.context.mfa,
                    authenticated_at=auth_session.context.authenticated_at,
                ),
                correlation_id="postgres-e2e",
            )
        )
        assert decision.allowed is True
        assert decision.reason_code is AuthorizationReason.ALLOW_ROLE_PERMISSION_MATCH

    with factory() as session:
        persisted_identity = SqlAlchemyIdentityRepository(session).get(identity.id)
        persisted_credential = SqlAlchemyCredentialRepository(session).get(credential.id)
        persisted_factor = SqlAlchemyMfaFactorRepository(session).get(factor.id)
        persisted_session = SqlAlchemySessionRepository(session).get(auth_session.id)
        persisted_binding = SqlAlchemyRoleBindingRepository(session).get(binding.id)
        persisted_provisioning = SqlAlchemyProvisioningUserRepository(session).get(
            provisioning_user.id
        )
        persisted_constraints = SqlAlchemyConstraintRepository(session).list_for(
            permission.code,
            tenant.id,
        )
        audit_events = SqlAlchemyAuditRepository(session).by_correlation_id("postgres-e2e")
        assert persisted_identity is not None
        assert persisted_identity.id == identity.id
        assert persisted_credential == credential
        assert persisted_factor == factor
        assert persisted_session == auth_session
        assert persisted_session is not None
        assert persisted_session.context.assurance_level is AssuranceLevel.AAL2
        assert persisted_session.context.mfa is True
        assert persisted_session.context.mfa_factor_id == str(factor.id)
        assert persisted_binding == binding
        assert persisted_provisioning == provisioning_user
        assert any(rule == assurance_rule for rule in persisted_constraints)
        assert len(audit_events) == 1
        assert audit_events[0].outcome is not None
        assert audit_events[0].outcome.value == "allow"

    drop_schema(engine)
    engine.dispose()
