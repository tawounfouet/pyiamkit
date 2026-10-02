from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from pyiamkit.identity import IdentityId
from pyiamkit.operations import StateVersion
from pyiamkit.persistence.sqlalchemy import (
    SqlAlchemySecurityStateStore,
    create_schema,
    create_session_factory,
    create_sqlalchemy_engine,
)
from pyiamkit.tenancy import TenantId


@pytest.fixture
def security_state_session(tmp_path: Path) -> Iterator[Session]:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'security-state.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.mark.conformance
def test_sqlalchemy_security_state_defaults_to_zero(
    security_state_session: Session,
) -> None:
    store = SqlAlchemySecurityStateStore(security_state_session)

    stamp = store.stamp_for(
        identity_id=IdentityId.new(),
        tenant_id=TenantId.new(),
    )

    assert stamp.runtime_generation == StateVersion(0)
    assert stamp.identity == StateVersion(0)
    assert stamp.tenant == StateVersion(0)
    assert stamp.membership == StateVersion(0)
    assert stamp.subject_authorization == StateVersion(0)
    assert stamp.tenant_authorization == StateVersion(0)
    assert stamp.global_authorization == StateVersion(0)
    assert stamp.governance == StateVersion(0)
    assert stamp.authentication == StateVersion(0)


@pytest.mark.conformance
def test_sqlalchemy_security_state_round_trip_and_scope_isolation(
    security_state_session: Session,
) -> None:
    store = SqlAlchemySecurityStateStore(security_state_session)
    identity_a = IdentityId.new()
    identity_b = IdentityId.new()
    tenant_a = TenantId.new()
    tenant_b = TenantId.new()

    assert store.bump_runtime_generation() == StateVersion(1)
    assert store.bump_identity(identity_a) == StateVersion(1)
    assert store.bump_identity(identity_a) == StateVersion(2)
    assert store.bump_tenant(tenant_a) == StateVersion(1)
    assert store.bump_membership(identity_a, tenant_a) == StateVersion(1)
    assert store.bump_subject_authorization(identity_a, tenant_a) == StateVersion(1)
    assert store.bump_tenant_authorization(tenant_a) == StateVersion(1)
    assert store.bump_global_authorization() == StateVersion(1)
    assert store.bump_governance(tenant_a) == StateVersion(1)
    assert store.bump_authentication(identity_a) == StateVersion(1)

    stamp = store.stamp_for(identity_id=identity_a, tenant_id=tenant_a)
    other_subject = store.stamp_for(identity_id=identity_b, tenant_id=tenant_a)
    other_tenant = store.stamp_for(identity_id=identity_a, tenant_id=tenant_b)

    assert stamp.runtime_generation == StateVersion(1)
    assert stamp.identity == StateVersion(2)
    assert stamp.tenant == StateVersion(1)
    assert stamp.membership == StateVersion(1)
    assert stamp.subject_authorization == StateVersion(1)
    assert stamp.tenant_authorization == StateVersion(1)
    assert stamp.global_authorization == StateVersion(1)
    assert stamp.governance == StateVersion(1)
    assert stamp.authentication == StateVersion(1)

    assert other_subject.identity == StateVersion(0)
    assert other_subject.membership == StateVersion(0)
    assert other_subject.subject_authorization == StateVersion(0)
    assert other_subject.authentication == StateVersion(0)
    assert other_subject.tenant == StateVersion(1)
    assert other_subject.tenant_authorization == StateVersion(1)
    assert other_subject.governance == StateVersion(1)
    assert other_subject.global_authorization == StateVersion(1)

    assert other_tenant.identity == StateVersion(2)
    assert other_tenant.authentication == StateVersion(1)
    assert other_tenant.tenant == StateVersion(0)
    assert other_tenant.membership == StateVersion(0)
    assert other_tenant.subject_authorization == StateVersion(0)
    assert other_tenant.tenant_authorization == StateVersion(0)
    assert other_tenant.governance == StateVersion(0)
    assert other_tenant.global_authorization == StateVersion(1)


@pytest.mark.conformance
def test_sqlalchemy_security_state_follows_caller_transaction_boundary(
    tmp_path: Path,
) -> None:
    engine = create_sqlalchemy_engine(f"sqlite+pysqlite:///{tmp_path / 'rollback-state.db'}")
    create_schema(engine)
    factory = create_session_factory(engine)
    identity_id = IdentityId.new()
    tenant_id = TenantId.new()

    with factory() as session:
        store = SqlAlchemySecurityStateStore(session)
        assert store.bump_identity(identity_id) == StateVersion(1)
        assert store.stamp_for(
            identity_id=identity_id, tenant_id=tenant_id
        ).identity == StateVersion(1)
        session.rollback()

    with factory() as session:
        stamp = SqlAlchemySecurityStateStore(session).stamp_for(
            identity_id=identity_id,
            tenant_id=tenant_id,
        )
        assert stamp.identity == StateVersion(0)

    with factory.begin() as session:
        store = SqlAlchemySecurityStateStore(session)
        assert store.bump_identity(identity_id) == StateVersion(1)
        assert store.bump_authentication(identity_id) == StateVersion(1)

    with factory() as session:
        stamp = SqlAlchemySecurityStateStore(session).stamp_for(
            identity_id=identity_id,
            tenant_id=tenant_id,
        )
        assert stamp.identity == StateVersion(1)
        assert stamp.authentication == StateVersion(1)

    engine.dispose()
