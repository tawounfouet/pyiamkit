"""SQLAlchemy implementations of Authorization persistence ports."""

from datetime import datetime

from sqlalchemy import delete, func, insert, or_, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from pyiamkit.authorization import (
    AuthorizationConstraint,
    DistinctActorSoDRule,
    GovernanceRuleId,
    GrantSource,
    MutuallyExclusiveRolesRule,
    NumericMaximumConstraint,
    Permission,
    PermissionCode,
    ResourceAttributeEqualsConstraint,
    Role,
    RoleBinding,
    RoleBindingId,
    RoleBindingStatus,
    RoleId,
    RoleStatus,
    RoleType,
)
from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId, TenantScope

from .common import (
    decimal_from_db,
    optional_utc_from_db,
    optional_uuid_from_db,
    utc_from_db,
    uuid_from_db,
    upsert,
)
from .schema import (
    constraint_table,
    permission_table,
    role_binding_table,
    role_parent_table,
    role_permission_table,
    role_table,
    sod_rule_table,
)


class SqlAlchemyPermissionCatalogRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, code: PermissionCode) -> Permission | None:
        row = self._session.execute(
            select(permission_table).where(permission_table.c.code == str(code))
        ).mappings().one_or_none()
        if row is None:
            return None
        return Permission(
            code=PermissionCode(str(row["code"])),
            description=str(row["description"]),
            sensitive=bool(row["sensitive"]),
        )

    def save(self, permission: Permission) -> None:
        upsert(
            self._session,
            permission_table,
            permission_table.c.code == str(permission.code),
            {
                "code": str(permission.code),
                "description": permission.description,
                "sensitive": permission.sensitive,
            },
        )


class SqlAlchemyRoleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, role_id: RoleId) -> Role | None:
        row = self._session.execute(
            select(role_table).where(role_table.c.id == role_id.value)
        ).mappings().one_or_none()
        return None if row is None else self._rehydrate(row)

    def save(self, role: Role) -> None:
        upsert(
            self._session,
            role_table,
            role_table.c.id == role.id.value,
            {
                "id": role.id.value,
                "version": role.version,
                "name": role.name,
                "role_type": role.role_type.value,
                "status": role.status.value,
                "tenant_id": None if role.tenant_id is None else role.tenant_id.value,
                "assignable": role.assignable,
                "sensitive": role.sensitive,
                "created_at": role.created_at,
                "updated_at": role.updated_at,
            },
        )
        self._session.execute(
            delete(role_permission_table).where(role_permission_table.c.role_id == role.id.value)
        )
        if role.permissions:
            self._session.execute(
                insert(role_permission_table),
                [
                    {"role_id": role.id.value, "permission_code": str(code)}
                    for code in sorted(role.permissions, key=str)
                ],
            )
        self._session.execute(
            delete(role_parent_table).where(role_parent_table.c.role_id == role.id.value)
        )
        if role.parent_role_ids:
            self._session.execute(
                insert(role_parent_table),
                [
                    {"role_id": role.id.value, "parent_role_id": parent.value}
                    for parent in sorted(role.parent_role_ids, key=str)
                ],
            )

    def find_by_name(self, tenant_id: TenantId | None, name: str) -> Role | None:
        statement = select(role_table).where(func.lower(role_table.c.name) == name.strip().lower())
        if tenant_id is None:
            statement = statement.where(role_table.c.tenant_id.is_(None))
        else:
            statement = statement.where(role_table.c.tenant_id == tenant_id.value)
        row = self._session.execute(statement).mappings().one_or_none()
        return None if row is None else self._rehydrate(row)

    def _rehydrate(self, row: RowMapping) -> Role:
        role_uuid = uuid_from_db(row["id"])
        permissions = frozenset(
            PermissionCode(str(value))
            for value in self._session.execute(
                select(role_permission_table.c.permission_code)
                .where(role_permission_table.c.role_id == role_uuid)
                .order_by(role_permission_table.c.permission_code)
            ).scalars()
        )
        parents = frozenset(
            RoleId(uuid_from_db(value))
            for value in self._session.execute(
                select(role_parent_table.c.parent_role_id)
                .where(role_parent_table.c.role_id == role_uuid)
                .order_by(role_parent_table.c.parent_role_id)
            ).scalars()
        )
        tenant_uuid = optional_uuid_from_db(row["tenant_id"])
        return Role._rehydrate(
            role_id=RoleId(role_uuid),
            version=int(row["version"]),
            name=str(row["name"]),
            role_type=RoleType(str(row["role_type"])),
            status=RoleStatus(str(row["status"])),
            tenant_id=None if tenant_uuid is None else TenantId(tenant_uuid),
            assignable=bool(row["assignable"]),
            sensitive=bool(row["sensitive"]),
            permissions=permissions,
            parent_role_ids=parents,
            created_at=utc_from_db(row["created_at"]),
            updated_at=utc_from_db(row["updated_at"]),
        )


class SqlAlchemyRoleBindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, binding_id: RoleBindingId) -> RoleBinding | None:
        row = self._session.execute(
            select(role_binding_table).where(role_binding_table.c.id == binding_id.value)
        ).mappings().one_or_none()
        return None if row is None else _binding_from_row(row)

    def save(self, binding: RoleBinding) -> None:
        upsert(
            self._session,
            role_binding_table,
            role_binding_table.c.id == binding.id.value,
            {
                "id": binding.id.value,
                "version": binding.version,
                "identity_id": binding.identity_id.value,
                "role_id": binding.role_id.value,
                "tenant_id": binding.tenant_id.value,
                "scope_tenant_id": binding.scope.tenant_id.value,
                "status": binding.status.value,
                "grant_source": binding.grant_source.value,
                "granted_by": None if binding.granted_by is None else binding.granted_by.value,
                "justification": binding.justification,
                "created_at": binding.created_at,
                "updated_at": binding.updated_at,
                "valid_from": binding.valid_from,
                "valid_until": binding.valid_until,
            },
        )

    def find_for_subject(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> tuple[RoleBinding, ...]:
        rows = self._session.execute(
            select(role_binding_table)
            .where(
                role_binding_table.c.identity_id == identity_id.value,
                role_binding_table.c.tenant_id == tenant_id.value,
            )
            .order_by(role_binding_table.c.created_at, role_binding_table.c.id)
        ).mappings().all()
        return tuple(_binding_from_row(row) for row in rows)

    def find_active_for_subject(
        self,
        identity_id: IdentityId,
        tenant_id: TenantId,
        at: datetime,
    ) -> tuple[RoleBinding, ...]:
        rows = self._session.execute(
            select(role_binding_table)
            .where(
                role_binding_table.c.identity_id == identity_id.value,
                role_binding_table.c.tenant_id == tenant_id.value,
                role_binding_table.c.status == RoleBindingStatus.ACTIVE.value,
                role_binding_table.c.valid_from <= at,
                or_(role_binding_table.c.valid_until.is_(None), role_binding_table.c.valid_until > at),
            )
            .order_by(role_binding_table.c.created_at, role_binding_table.c.id)
        ).mappings().all()
        return tuple(_binding_from_row(row) for row in rows)


class SqlAlchemyConstraintRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, constraint: AuthorizationConstraint) -> None:
        if isinstance(constraint, NumericMaximumConstraint):
            kind = "numeric_maximum"
            maximum = constraint.maximum
            expected_value = None
        else:
            kind = "resource_attribute_equals"
            maximum = None
            expected_value = constraint.expected_value
        upsert(
            self._session,
            constraint_table,
            constraint_table.c.id == constraint.id.value,
            {
                "id": constraint.id.value,
                "kind": kind,
                "permission_code": str(constraint.permission),
                "tenant_id": None if constraint.tenant_id is None else constraint.tenant_id.value,
                "resource_attribute": constraint.resource_attribute,
                "maximum": maximum,
                "expected_value": expected_value,
            },
        )

    def list_for(
        self,
        permission: PermissionCode,
        tenant_id: TenantId,
    ) -> tuple[AuthorizationConstraint, ...]:
        rows = self._session.execute(
            select(constraint_table)
            .where(
                constraint_table.c.permission_code == str(permission),
                or_(
                    constraint_table.c.tenant_id.is_(None),
                    constraint_table.c.tenant_id == tenant_id.value,
                ),
            )
            .order_by(constraint_table.c.id)
        ).mappings().all()
        return tuple(_constraint_from_row(row) for row in rows)


class SqlAlchemySoDRuleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def save_static(self, rule: MutuallyExclusiveRolesRule) -> None:
        upsert(
            self._session,
            sod_rule_table,
            sod_rule_table.c.id == rule.id.value,
            {
                "id": rule.id.value,
                "kind": "static_roles",
                "name": rule.name,
                "tenant_id": None if rule.tenant_id is None else rule.tenant_id.value,
                "first_role_id": rule.first_role_id.value,
                "second_role_id": rule.second_role_id.value,
                "permission_code": None,
                "resource_attribute": None,
            },
        )

    def save_dynamic(self, rule: DistinctActorSoDRule) -> None:
        upsert(
            self._session,
            sod_rule_table,
            sod_rule_table.c.id == rule.id.value,
            {
                "id": rule.id.value,
                "kind": "dynamic_actor",
                "name": rule.name,
                "tenant_id": None if rule.tenant_id is None else rule.tenant_id.value,
                "first_role_id": None,
                "second_role_id": None,
                "permission_code": str(rule.permission),
                "resource_attribute": rule.resource_attribute,
            },
        )

    def list_static(self, tenant_id: TenantId) -> tuple[MutuallyExclusiveRolesRule, ...]:
        rows = self._session.execute(
            select(sod_rule_table)
            .where(
                sod_rule_table.c.kind == "static_roles",
                or_(
                    sod_rule_table.c.tenant_id.is_(None),
                    sod_rule_table.c.tenant_id == tenant_id.value,
                ),
            )
            .order_by(sod_rule_table.c.id)
        ).mappings().all()
        return tuple(_static_sod_from_row(row) for row in rows)

    def list_dynamic(
        self,
        permission: PermissionCode,
        tenant_id: TenantId,
    ) -> tuple[DistinctActorSoDRule, ...]:
        rows = self._session.execute(
            select(sod_rule_table)
            .where(
                sod_rule_table.c.kind == "dynamic_actor",
                sod_rule_table.c.permission_code == str(permission),
                or_(
                    sod_rule_table.c.tenant_id.is_(None),
                    sod_rule_table.c.tenant_id == tenant_id.value,
                ),
            )
            .order_by(sod_rule_table.c.id)
        ).mappings().all()
        return tuple(_dynamic_sod_from_row(row) for row in rows)


def _binding_from_row(row: RowMapping) -> RoleBinding:
    granted_by_uuid = optional_uuid_from_db(row["granted_by"])
    return RoleBinding._rehydrate(
        binding_id=RoleBindingId(uuid_from_db(row["id"])),
        version=int(row["version"]),
        identity_id=IdentityId(uuid_from_db(row["identity_id"])),
        role_id=RoleId(uuid_from_db(row["role_id"])),
        tenant_id=TenantId(uuid_from_db(row["tenant_id"])),
        scope=TenantScope(TenantId(uuid_from_db(row["scope_tenant_id"]))),
        status=RoleBindingStatus(str(row["status"])),
        grant_source=GrantSource(str(row["grant_source"])),
        granted_by=None if granted_by_uuid is None else IdentityId(granted_by_uuid),
        justification=None if row["justification"] is None else str(row["justification"]),
        created_at=utc_from_db(row["created_at"]),
        updated_at=utc_from_db(row["updated_at"]),
        valid_from=utc_from_db(row["valid_from"]),
        valid_until=optional_utc_from_db(row["valid_until"]),
    )


def _constraint_from_row(row: RowMapping) -> AuthorizationConstraint:
    tenant_uuid = optional_uuid_from_db(row["tenant_id"])
    tenant_id = None if tenant_uuid is None else TenantId(tenant_uuid)
    rule_id = GovernanceRuleId(uuid_from_db(row["id"]))
    permission = PermissionCode(str(row["permission_code"]))
    resource_attribute = str(row["resource_attribute"])
    if str(row["kind"]) == "numeric_maximum":
        return NumericMaximumConstraint(
            id=rule_id,
            permission=permission,
            resource_attribute=resource_attribute,
            maximum=decimal_from_db(row["maximum"]),
            tenant_id=tenant_id,
        )
    return ResourceAttributeEqualsConstraint(
        id=rule_id,
        permission=permission,
        resource_attribute=resource_attribute,
        expected_value=str(row["expected_value"]),
        tenant_id=tenant_id,
    )


def _static_sod_from_row(row: RowMapping) -> MutuallyExclusiveRolesRule:
    tenant_uuid = optional_uuid_from_db(row["tenant_id"])
    return MutuallyExclusiveRolesRule(
        id=GovernanceRuleId(uuid_from_db(row["id"])),
        name=str(row["name"]),
        first_role_id=RoleId(uuid_from_db(row["first_role_id"])),
        second_role_id=RoleId(uuid_from_db(row["second_role_id"])),
        tenant_id=None if tenant_uuid is None else TenantId(tenant_uuid),
    )


def _dynamic_sod_from_row(row: RowMapping) -> DistinctActorSoDRule:
    tenant_uuid = optional_uuid_from_db(row["tenant_id"])
    return DistinctActorSoDRule(
        id=GovernanceRuleId(uuid_from_db(row["id"])),
        name=str(row["name"]),
        permission=PermissionCode(str(row["permission_code"])),
        resource_attribute=str(row["resource_attribute"]),
        tenant_id=None if tenant_uuid is None else TenantId(tenant_uuid),
    )
