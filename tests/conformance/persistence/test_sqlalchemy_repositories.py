from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from pyiamkit.audit import AuditCategory, AuditEvent, AuditOutcome
from pyiamkit.authentication import AssuranceLevel
from pyiamkit.authorization import (
    DistinctActorSoDRule,
    GovernanceRuleId,
    MinimumAssuranceConstraint,
    MutuallyExclusiveRolesRule,
    NumericMaximumConstraint,
    Permission,
    PermissionCode,
    ResourceAttributeEqualsConstraint,
    Role,
    RoleBinding,
    RoleType,
)
from pyiamkit.identity import EmailAddress, Identity, IdentityStatus, ServiceAccount
from pyiamkit.persistence import PersistenceSerializationError
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemyAuditRepository,
    SqlAlchemyConstraintRepository,
    SqlAlchemyIdentityRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyPermissionCatalogRepository,
    SqlAlchemyProvisioningUserRepository,
    SqlAlchemyRoleBindingRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemySoDRuleRepository,
    SqlAlchemyTenantRepository,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
    drop_schema,
)
from pyiamkit.persistence.sqlalchemy.schema import identity_table
from pyiamkit.provisioning import ProvisioningUser
from pyiamkit.tenancy import Membership, Tenant, TenantScope

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def db_session(tmp_path: Path) -> Iterator[Session]:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'pyiamkit.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        yield session
    engine.dispose()


def _active_identity(session: Session) -> Identity:
    identity = Identity.create_user(
        display_name="Alice",
        created_at=NOW,
        primary_email=EmailAddress("alice@example.com"),
        metadata={"department": "data"},
    )
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    SqlAlchemyIdentityRepository(session).save(identity)
    return identity


def _active_tenant(session: Session) -> Tenant:
    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW, metadata={"tier": "pro"})
    tenant.pull_events()
    tenant.activate(at=NOW)
    tenant.pull_events()
    SqlAlchemyTenantRepository(session).save(tenant)
    return tenant


def _active_membership(session: Session, identity: Identity, tenant: Tenant) -> Membership:
    membership = Membership.create(
        identity_id=identity.id,
        tenant_id=tenant.id,
        created_at=NOW,
        source="test",
    )
    membership.pull_events()
    membership.activate(at=NOW)
    membership.pull_events()
    SqlAlchemyMembershipRepository(session).save(membership)
    return membership


@pytest.mark.conformance
def test_identity_repository_round_trip_and_external_lookup(db_session: Session) -> None:
    repository = SqlAlchemyIdentityRepository(db_session)
    identity = Identity.create_user(
        display_name="Alice",
        created_at=NOW,
        primary_email=EmailAddress("Alice@Example.COM"),
        metadata={"department": "data"},
    )
    identity.pull_events()
    identity.activate(at=NOW)
    identity.pull_events()
    identity.link_external_identity(
        provider_id="entra",
        external_subject="alice-123",
        at=NOW,
    )
    identity.pull_events()

    repository.save(identity)
    loaded = repository.get(identity.id)

    assert loaded is not None
    assert loaded.status is IdentityStatus.ACTIVE
    assert str(loaded.profile.primary_email) == "Alice@example.com"  # type: ignore[union-attr]
    assert loaded.metadata["department"] == "data"
    assert loaded.external_links[0].provider_id == "entra"
    assert repository.exists(identity.id) is True
    assert repository.find_by_external_subject(" entra ", " alice-123 ") == identity

    identity.disable(at=NOW + timedelta(minutes=1), reason="offboarding")
    identity.pull_events()
    repository.save(identity)
    assert repository.get(identity.id).status is IdentityStatus.DISABLED  # type: ignore[union-attr]


@pytest.mark.conformance
def test_service_account_profile_round_trip(db_session: Session) -> None:
    repository = SqlAlchemyIdentityRepository(db_session)
    owner = _active_identity(db_session)
    service_account = Identity.create_service_account(
        display_name="Billing Worker",
        name="billing-worker",
        owner_identity_id=owner.id,
        purpose="Process billing jobs",
        environment="prod",
        expires_at=NOW + timedelta(days=30),
        created_at=NOW,
    )
    service_account.pull_events()
    service_account.activate(at=NOW)
    service_account.pull_events()
    repository.save(service_account)

    loaded = repository.get(service_account.id)
    assert loaded is not None
    assert isinstance(loaded.profile, ServiceAccount)
    assert loaded.profile.owner_identity_id == owner.id
    assert loaded.profile.expires_at == NOW + timedelta(days=30)


@pytest.mark.conformance
def test_non_json_identity_metadata_fails_at_adapter_boundary(db_session: Session) -> None:
    identity = Identity.create_user(
        display_name="Alice",
        created_at=NOW,
        metadata={"not_json": object()},
    )
    with pytest.raises(PersistenceSerializationError):
        SqlAlchemyIdentityRepository(db_session).save(identity)


@pytest.mark.conformance
def test_tenant_and_membership_repositories_round_trip(db_session: Session) -> None:
    identity = _active_identity(db_session)
    tenant = _active_tenant(db_session)
    membership = _active_membership(db_session, identity, tenant)

    tenant_repository = SqlAlchemyTenantRepository(db_session)
    membership_repository = SqlAlchemyMembershipRepository(db_session)

    loaded_tenant = tenant_repository.find_by_slug(" ACME ")
    assert loaded_tenant is not None
    assert loaded_tenant.id == tenant.id
    assert loaded_tenant.metadata["tier"] == "pro"

    loaded_membership = membership_repository.get(membership.id)
    assert loaded_membership is not None
    assert loaded_membership.identity_id == identity.id

    found_membership = membership_repository.find(identity.id, tenant.id)
    assert found_membership is not None
    assert found_membership.id == loaded_membership.id

    active_membership = membership_repository.find_active(identity.id, tenant.id, NOW)
    assert active_membership is not None
    assert active_membership.id == loaded_membership.id

    active_later = membership_repository.find_active(
        identity.id,
        tenant.id,
        NOW + timedelta(days=1),
    )
    assert active_later is not None
    assert active_later.id == loaded_membership.id


@pytest.mark.conformance
def test_provisioning_repository_round_trip_tombstone_and_reprovision(
    db_session: Session,
) -> None:
    identity = _active_identity(db_session)
    tenant = _active_tenant(db_session)
    membership = _active_membership(db_session, identity, tenant)
    repository = SqlAlchemyProvisioningUserRepository(db_session)

    resource = ProvisioningUser.create(
        source_id="entra-scim",
        identity_id=identity.id,
        tenant_id=tenant.id,
        membership_id=membership.id,
        user_name="Alice@Example.com",
        external_id="external-42",
        active=True,
        created_at=NOW,
    )
    repository.save(resource)

    loaded = repository.get(resource.id)
    assert loaded == resource
    assert repository.find_by_user_name("entra-scim", "alice@example.COM") == resource
    assert repository.find_by_external_id("entra-scim", "external-42") == resource
    assert repository.list_for_source("entra-scim", tenant.id) == (resource,)

    resource.delete(at=NOW + timedelta(minutes=1))
    repository.save(resource)
    assert repository.find_by_user_name("entra-scim", "alice@example.com") is None
    assert repository.find_by_external_id("entra-scim", "external-42") is None
    assert repository.list_for_source("entra-scim", tenant.id) == ()

    reprovisioned = ProvisioningUser.create(
        source_id="entra-scim",
        identity_id=identity.id,
        tenant_id=tenant.id,
        membership_id=membership.id,
        user_name="alice@example.com",
        external_id="external-42",
        active=True,
        created_at=NOW + timedelta(minutes=2),
    )
    repository.save(reprovisioned)
    assert repository.find_by_user_name("entra-scim", "ALICE@EXAMPLE.COM") == reprovisioned


@pytest.mark.conformance
def test_role_permission_hierarchy_and_binding_round_trip(db_session: Session) -> None:
    identity = _active_identity(db_session)
    tenant = _active_tenant(db_session)
    _active_membership(db_session, identity, tenant)

    permission_repository = SqlAlchemyPermissionCatalogRepository(db_session)
    role_repository = SqlAlchemyRoleRepository(db_session)
    binding_repository = SqlAlchemyRoleBindingRepository(db_session)

    permission = Permission(PermissionCode("invoice.read"), "Read invoices")
    permission_repository.save(permission)

    parent = Role.create(name="Base Reader", role_type=RoleType.BUSINESS, created_at=NOW)
    parent.pull_events()
    parent.add_permission(permission.code, at=NOW)
    parent.pull_events()
    role_repository.save(parent)

    child = Role.create(
        name="Tenant Manager",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    child.pull_events()
    child.add_parent_role(parent.id, at=NOW)
    child.pull_events()
    role_repository.save(child)

    loaded_child = role_repository.get(child.id)
    assert loaded_child is not None
    assert loaded_child.parent_role_ids == frozenset({parent.id})
    found_child = role_repository.find_by_name(tenant.id, "tenant manager")
    assert found_child is not None
    assert found_child.id == loaded_child.id
    assert found_child.parent_role_ids == loaded_child.parent_role_ids
    assert permission_repository.get(permission.code) == permission

    binding = RoleBinding.create(
        identity_id=identity.id,
        role_id=child.id,
        tenant_id=tenant.id,
        scope=TenantScope(tenant.id),
        created_at=NOW,
        valid_until=NOW + timedelta(hours=1),
    )
    binding.pull_events()
    binding_repository.save(binding)

    assert binding_repository.get(binding.id) == binding
    assert binding_repository.find_for_subject(identity.id, tenant.id) == (binding,)
    assert binding_repository.find_active_for_subject(identity.id, tenant.id, NOW) == (binding,)
    assert (
        binding_repository.find_active_for_subject(
            identity.id,
            tenant.id,
            NOW + timedelta(hours=2),
        )
        == ()
    )


@pytest.mark.conformance
def test_constraints_and_sod_rules_round_trip(db_session: Session) -> None:
    tenant = _active_tenant(db_session)
    other_tenant = Tenant.create(name="OTHER", slug="other", created_at=NOW)
    other_tenant.pull_events()
    other_tenant.activate(at=NOW)
    other_tenant.pull_events()
    SqlAlchemyTenantRepository(db_session).save(other_tenant)

    permission_repository = SqlAlchemyPermissionCatalogRepository(db_session)
    role_repository = SqlAlchemyRoleRepository(db_session)
    constraint_repository = SqlAlchemyConstraintRepository(db_session)
    sod_repository = SqlAlchemySoDRuleRepository(db_session)

    permission = Permission(PermissionCode("payment.approve"), "Approve payments")
    permission_repository.save(permission)
    maker = Role.create(
        name="Maker",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    checker = Role.create(
        name="Checker",
        role_type=RoleType.TENANT,
        tenant_id=tenant.id,
        created_at=NOW,
    )
    maker.pull_events()
    checker.pull_events()
    role_repository.save(maker)
    role_repository.save(checker)

    global_limit = NumericMaximumConstraint(
        id=GovernanceRuleId.new(),
        permission=permission.code,
        resource_attribute="amount",
        maximum=Decimal("10000"),
    )
    tenant_currency = ResourceAttributeEqualsConstraint(
        id=GovernanceRuleId.new(),
        permission=permission.code,
        resource_attribute="currency",
        expected_value="EUR",
        tenant_id=tenant.id,
    )
    excluded = ResourceAttributeEqualsConstraint(
        id=GovernanceRuleId.new(),
        permission=permission.code,
        resource_attribute="currency",
        expected_value="USD",
        tenant_id=other_tenant.id,
    )
    assurance = MinimumAssuranceConstraint(
        id=GovernanceRuleId.new(),
        permission=permission.code,
        minimum_assurance=AssuranceLevel.AAL2,
        require_mfa=True,
        tenant_id=tenant.id,
    )
    constraint_repository.save(global_limit)
    constraint_repository.save(tenant_currency)
    constraint_repository.save(excluded)
    constraint_repository.save(assurance)

    constraints = constraint_repository.list_for(permission.code, tenant.id)
    assert {rule.id for rule in constraints} == {
        global_limit.id,
        tenant_currency.id,
        assurance.id,
    }
    persisted_assurance = next(
        rule for rule in constraints if isinstance(rule, MinimumAssuranceConstraint)
    )
    assert persisted_assurance.minimum_assurance is AssuranceLevel.AAL2
    assert persisted_assurance.require_mfa is True

    static_rule = MutuallyExclusiveRolesRule(
        id=GovernanceRuleId.new(),
        name="maker-checker",
        first_role_id=maker.id,
        second_role_id=checker.id,
        tenant_id=tenant.id,
    )
    dynamic_rule = DistinctActorSoDRule(
        id=GovernanceRuleId.new(),
        name="different-preparer",
        permission=permission.code,
        resource_attribute="prepared_by",
    )
    sod_repository.save_static(static_rule)
    sod_repository.save_dynamic(dynamic_rule)

    assert sod_repository.list_static(tenant.id) == (static_rule,)
    assert sod_repository.list_dynamic(permission.code, tenant.id) == (dynamic_rule,)


@pytest.mark.conformance
def test_audit_repository_is_append_only_and_queryable(db_session: Session) -> None:
    repository = SqlAlchemyAuditRepository(db_session)
    first = AuditEvent(
        category=AuditCategory.AUTHORIZATION,
        event_type="AuthorizationDecision",
        occurred_at=NOW,
        subject_id="user:1",
        tenant_id="tenant:1",
        action="invoice.read",
        outcome=AuditOutcome.ALLOW,
        correlation_id="req-1",
        metadata={"reason": "role"},
    )
    second = AuditEvent(
        category=AuditCategory.DOMAIN,
        event_type="RoleAssigned",
        occurred_at=NOW + timedelta(seconds=1),
        actor_id="admin:1",
        subject_id="user:1",
        correlation_id="req-2",
    )
    repository.append(first)
    repository.append(second)

    assert repository.all() == (first, second)
    assert repository.by_correlation_id("req-1") == (first,)
    assert repository.by_subject("user:1") == (first, second)

    with pytest.raises(ValueError, match="already exists"):
        repository.append(first)
    assert repository.all() == (first, second)


@pytest.mark.conformance
def test_repository_writes_follow_caller_transaction_boundary(tmp_path: Path) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'rollback.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    identity = Identity.create_user(display_name="Rollback", created_at=NOW)

    with factory() as session:
        SqlAlchemyIdentityRepository(session).save(identity)
        assert SqlAlchemyIdentityRepository(session).exists(identity.id) is True
        session.rollback()

    with factory() as session:
        assert SqlAlchemyIdentityRepository(session).exists(identity.id) is False

    drop_schema(engine)
    engine.dispose()


@pytest.mark.conformance
def test_schema_compiles_to_postgresql_uuid_and_jsonb() -> None:
    ddl = str(CreateTable(identity_table).compile(dialect=postgresql.dialect()))
    assert "UUID" in ddl
    assert "JSONB" in ddl
