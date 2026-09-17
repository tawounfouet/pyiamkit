from datetime import UTC, datetime

import pytest

from pyiamkit.tenancy import InvalidTenantTransition, Tenant, TenantStatus

NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_tenant_lifecycle_is_explicit() -> None:
    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    assert tenant.status is TenantStatus.PENDING
    assert tenant.pull_events()[0].event_type == "TenantCreated"

    tenant.activate(at=NOW)
    tenant.suspend(at=NOW)
    tenant.reactivate(at=NOW)
    tenant.disable(at=NOW)
    tenant.archive(at=NOW)

    assert tenant.status is TenantStatus.ARCHIVED


def test_archived_tenant_cannot_be_reactivated() -> None:
    tenant = Tenant.create(name="ACME", slug="acme", created_at=NOW)
    tenant.activate(at=NOW)
    tenant.disable(at=NOW)
    tenant.archive(at=NOW)

    with pytest.raises(InvalidTenantTransition):
        tenant.reactivate(at=NOW)


def test_tenant_slug_is_canonicalized() -> None:
    tenant = Tenant.create(name="ACME", slug=" Acme-Group ", created_at=NOW)
    assert tenant.slug == "acme-group"
