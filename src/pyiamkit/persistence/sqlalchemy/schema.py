"""Portable SQLAlchemy Core schema for PyIAMKit persistence adapters."""

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Numeric,
    String,
    Table,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)
json_type = JSON().with_variant(JSONB(), "postgresql")

identity_table = Table(
    "iam_identities",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("identity_type", String(32), nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("display_name", String(255), nullable=False),
    Column("profile", json_type, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("activated_at", DateTime(timezone=True)),
    Column("suspended_at", DateTime(timezone=True)),
    Column("disabled_at", DateTime(timezone=True)),
    Column("archived_at", DateTime(timezone=True)),
    Column("metadata_json", json_type, nullable=False),
)

identity_external_link_table = Table(
    "iam_identity_external_links",
    metadata,
    Column(
        "identity_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    ),
    Column("provider_id", String(255), primary_key=True),
    Column("external_subject", String(512), primary_key=True),
    Column("linked_at", DateTime(timezone=True), nullable=False),
)

credential_table = Table(
    "iam_credentials",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column(
        "identity_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_identities.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("credential_type", String(32), nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("reference", String(512), nullable=False, unique=True),
    Column("fingerprint", String(512)),
    Column("label", String(255)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("valid_from", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("metadata_json", json_type, nullable=False),
    CheckConstraint(
        "valid_until IS NULL OR valid_until > valid_from",
        name="credential_validity_interval",
    ),
)
Index(
    "ix_iam_credentials_identity_status",
    credential_table.c.identity_id,
    credential_table.c.status,
)

session_table = Table(
    "iam_sessions",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column(
        "identity_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_identities.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("status", String(32), nullable=False, index=True),
    Column("authentication_method", String(32), nullable=False),
    Column("assurance_level", String(16), nullable=False),
    Column("mfa", Boolean, nullable=False),
    Column("authenticated_at", DateTime(timezone=True), nullable=False),
    Column("provider_id", String(255)),
    Column("device_id", String(255)),
    Column("network_zone", String(255)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("last_activity_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("revocation_reason", Text),
    CheckConstraint("expires_at > created_at", name="session_expiry_after_creation"),
)
Index(
    "ix_iam_sessions_identity_status",
    session_table.c.identity_id,
    session_table.c.status,
)
Index(
    "ix_iam_sessions_identity_expires_at",
    session_table.c.identity_id,
    session_table.c.expires_at,
)

tenant_table = Table(
    "iam_tenants",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("name", String(255), nullable=False),
    Column("slug", String(63), nullable=False, unique=True),
    Column("status", String(32), nullable=False, index=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("metadata_json", json_type, nullable=False),
)

membership_table = Table(
    "iam_memberships",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column(
        "identity_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_identities.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "tenant_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_tenants.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("organization_id", Uuid(as_uuid=True)),
    Column("status", String(32), nullable=False, index=True),
    Column("source", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("valid_from", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True)),
)
Index(
    "uq_iam_memberships_identity_tenant",
    membership_table.c.identity_id,
    membership_table.c.tenant_id,
    unique=True,
)
Index(
    "ix_iam_memberships_identity_tenant_status",
    membership_table.c.identity_id,
    membership_table.c.tenant_id,
    membership_table.c.status,
)

permission_table = Table(
    "iam_permissions",
    metadata,
    Column("code", String(255), primary_key=True),
    Column("description", Text, nullable=False),
    Column("sensitive", Boolean, nullable=False),
)

role_table = Table(
    "iam_roles",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("name", String(255), nullable=False),
    Column("role_type", String(32), nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("tenant_id", Uuid(as_uuid=True), ForeignKey("iam_tenants.id", ondelete="CASCADE")),
    Column("assignable", Boolean, nullable=False),
    Column("sensitive", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)
Index(
    "uq_iam_roles_global_name",
    func.lower(role_table.c.name),
    unique=True,
    postgresql_where=role_table.c.tenant_id.is_(None),
    sqlite_where=role_table.c.tenant_id.is_(None),
)
Index(
    "uq_iam_roles_tenant_name",
    role_table.c.tenant_id,
    func.lower(role_table.c.name),
    unique=True,
    postgresql_where=role_table.c.tenant_id.is_not(None),
    sqlite_where=role_table.c.tenant_id.is_not(None),
)

role_permission_table = Table(
    "iam_role_permissions",
    metadata,
    Column(
        "role_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_code",
        String(255),
        ForeignKey("iam_permissions.code", ondelete="CASCADE"),
        primary_key=True,
    ),
)

role_parent_table = Table(
    "iam_role_parents",
    metadata,
    Column(
        "role_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "parent_role_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    CheckConstraint("role_id <> parent_role_id", name="role_parent_not_self"),
)

role_binding_table = Table(
    "iam_role_bindings",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("version", Integer, nullable=False),
    Column(
        "identity_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_identities.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "role_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_roles.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "tenant_id",
        Uuid(as_uuid=True),
        ForeignKey("iam_tenants.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("scope_tenant_id", Uuid(as_uuid=True), nullable=False),
    Column("status", String(32), nullable=False, index=True),
    Column("grant_source", String(32), nullable=False),
    Column("granted_by", Uuid(as_uuid=True), ForeignKey("iam_identities.id")),
    Column("justification", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("valid_from", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True)),
)
Index(
    "ix_iam_role_bindings_subject_tenant_status",
    role_binding_table.c.identity_id,
    role_binding_table.c.tenant_id,
    role_binding_table.c.status,
)

constraint_table = Table(
    "iam_constraints",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("kind", String(32), nullable=False),
    Column(
        "permission_code",
        String(255),
        ForeignKey("iam_permissions.code", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("tenant_id", Uuid(as_uuid=True), ForeignKey("iam_tenants.id", ondelete="CASCADE")),
    Column("resource_attribute", String(255), nullable=False),
    Column("maximum", Numeric(38, 18)),
    Column("expected_value", Text),
    CheckConstraint(
        "kind IN ('numeric_maximum', 'resource_attribute_equals')",
        name="constraint_kind",
    ),
)
Index(
    "ix_iam_constraints_permission_tenant",
    constraint_table.c.permission_code,
    constraint_table.c.tenant_id,
)

sod_rule_table = Table(
    "iam_sod_rules",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("kind", String(32), nullable=False),
    Column("name", String(255), nullable=False),
    Column("tenant_id", Uuid(as_uuid=True), ForeignKey("iam_tenants.id", ondelete="CASCADE")),
    Column("first_role_id", Uuid(as_uuid=True), ForeignKey("iam_roles.id", ondelete="CASCADE")),
    Column("second_role_id", Uuid(as_uuid=True), ForeignKey("iam_roles.id", ondelete="CASCADE")),
    Column("permission_code", String(255), ForeignKey("iam_permissions.code", ondelete="CASCADE")),
    Column("resource_attribute", String(255)),
    CheckConstraint("kind IN ('static_roles', 'dynamic_actor')", name="sod_rule_kind"),
)
Index("ix_iam_sod_rules_tenant_kind", sod_rule_table.c.tenant_id, sod_rule_table.c.kind)
Index(
    "ix_iam_sod_rules_permission_tenant",
    sod_rule_table.c.permission_code,
    sod_rule_table.c.tenant_id,
)

audit_event_table = Table(
    "iam_audit_events",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("category", String(32), nullable=False),
    Column("event_type", String(255), nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False, index=True),
    Column("actor_id", String(255)),
    Column("subject_id", String(255), index=True),
    Column("tenant_id", String(255)),
    Column("action", String(255)),
    Column("resource_type", String(255)),
    Column("resource_id", String(512)),
    Column("outcome", String(32)),
    Column("reason_code", String(255)),
    Column("correlation_id", String(255), index=True),
    Column("metadata_json", json_type, nullable=False),
)
Index(
    "ix_iam_audit_events_tenant_occurred_at",
    audit_event_table.c.tenant_id,
    audit_event_table.c.occurred_at,
)
