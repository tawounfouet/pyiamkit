"""Application and evaluation services for authorization governance rules."""

from decimal import Decimal, InvalidOperation

from pyiamkit.authentication import AssuranceLevel
from pyiamkit.shared import Clock, DomainEvent, DomainEventSink
from pyiamkit.tenancy import TenantId

from .domain.decision import AuthorizationRequest
from .domain.errors import (
    InvalidGovernanceRule,
    PermissionNotFound,
    RoleHierarchyError,
    RoleNotFound,
    StaticSoDViolation,
)
from .domain.governance import (
    DistinctActorSoDRule,
    GovernanceRuleId,
    GovernanceViolation,
    GovernanceViolationKind,
    MinimumAssuranceConstraint,
    MutuallyExclusiveRolesRule,
    NumericMaximumConstraint,
    ResourceAttributeEqualsConstraint,
)
from .domain.role import Role
from .domain.role_binding import RoleBinding
from .domain.value_objects import PermissionCode, RoleId
from .hierarchy import RoleHierarchyResolver
from .ports import (
    ConstraintRepository,
    PermissionCatalogRepository,
    RoleRepository,
    SoDRuleRepository,
)

_MISSING = object()


class AccessGovernanceApplicationService:
    """Register immutable constraint and SoD rules."""

    def __init__(
        self,
        *,
        permission_repository: PermissionCatalogRepository,
        role_repository: RoleRepository,
        constraint_repository: ConstraintRepository,
        sod_repository: SoDRuleRepository,
        clock: Clock,
        event_sink: DomainEventSink,
    ) -> None:
        self._permissions = permission_repository
        self._roles = role_repository
        self._constraints = constraint_repository
        self._sod = sod_repository
        self._clock = clock
        self._events = event_sink

    def register_numeric_maximum(
        self,
        permission: str,
        *,
        resource_attribute: str,
        maximum: Decimal,
        tenant_id: TenantId | None = None,
    ) -> NumericMaximumConstraint:
        code = self._require_permission(permission)
        rule = NumericMaximumConstraint(
            id=GovernanceRuleId.new(),
            permission=code,
            resource_attribute=resource_attribute,
            maximum=maximum,
            tenant_id=tenant_id,
        )
        self._constraints.save(rule)
        self._publish("AuthorizationConstraintRegistered", rule.id)
        return rule

    def register_resource_attribute_equals(
        self,
        permission: str,
        *,
        resource_attribute: str,
        expected_value: str,
        tenant_id: TenantId | None = None,
    ) -> ResourceAttributeEqualsConstraint:
        code = self._require_permission(permission)
        rule = ResourceAttributeEqualsConstraint(
            id=GovernanceRuleId.new(),
            permission=code,
            resource_attribute=resource_attribute,
            expected_value=expected_value,
            tenant_id=tenant_id,
        )
        self._constraints.save(rule)
        self._publish("AuthorizationConstraintRegistered", rule.id)
        return rule

    def register_minimum_assurance(
        self,
        permission: str,
        *,
        minimum_assurance: AssuranceLevel,
        require_mfa: bool = False,
        tenant_id: TenantId | None = None,
    ) -> MinimumAssuranceConstraint:
        code = self._require_permission(permission)
        rule = MinimumAssuranceConstraint(
            id=GovernanceRuleId.new(),
            permission=code,
            minimum_assurance=minimum_assurance,
            require_mfa=require_mfa,
            tenant_id=tenant_id,
        )
        self._constraints.save(rule)
        self._publish("MinimumAssuranceConstraintRegistered", rule.id)
        return rule

    def register_mutually_exclusive_roles(
        self,
        *,
        name: str,
        first_role_id: RoleId,
        second_role_id: RoleId,
        tenant_id: TenantId | None = None,
    ) -> MutuallyExclusiveRolesRule:
        first = self._require_role(first_role_id)
        second = self._require_role(second_role_id)
        self._validate_rule_role_tenant(first.tenant_id, tenant_id)
        self._validate_rule_role_tenant(second.tenant_id, tenant_id)
        rule = MutuallyExclusiveRolesRule(
            id=GovernanceRuleId.new(),
            name=name,
            first_role_id=first_role_id,
            second_role_id=second_role_id,
            tenant_id=tenant_id,
        )
        self._sod.save_static(rule)
        self._publish("StaticSoDRuleRegistered", rule.id)
        return rule

    def register_distinct_actor_sod(
        self,
        permission: str,
        *,
        name: str,
        resource_attribute: str,
        tenant_id: TenantId | None = None,
    ) -> DistinctActorSoDRule:
        code = self._require_permission(permission)
        rule = DistinctActorSoDRule(
            id=GovernanceRuleId.new(),
            name=name,
            permission=code,
            resource_attribute=resource_attribute,
            tenant_id=tenant_id,
        )
        self._sod.save_dynamic(rule)
        self._publish("DynamicSoDRuleRegistered", rule.id)
        return rule

    def _require_permission(self, permission: str) -> PermissionCode:
        code = PermissionCode(permission)
        if self._permissions.get(code) is None:
            raise PermissionNotFound(code)
        return code

    def _require_role(self, role_id: RoleId) -> Role:
        role = self._roles.get(role_id)
        if role is None:
            raise RoleNotFound(role_id)
        return role

    @staticmethod
    def _validate_rule_role_tenant(
        role_tenant_id: TenantId | None,
        rule_tenant_id: TenantId | None,
    ) -> None:
        if rule_tenant_id is None and role_tenant_id is not None:
            raise InvalidGovernanceRule("Global SoD rules may reference only global Roles.")
        if (
            rule_tenant_id is not None
            and role_tenant_id is not None
            and role_tenant_id != rule_tenant_id
        ):
            raise InvalidGovernanceRule("SoD rule Role belongs to a different tenant.")

    def _publish(self, event_type: str, rule_id: GovernanceRuleId) -> None:
        self._events.publish(
            (
                DomainEvent(
                    event_type=event_type,
                    occurred_at=self._clock.now(),
                    metadata={"rule_id": str(rule_id)},
                ),
            )
        )


class ConstraintEvaluator:
    def __init__(self, repository: ConstraintRepository) -> None:
        self._repository = repository

    def evaluate(self, request: AuthorizationRequest) -> GovernanceViolation | None:
        for rule in self._repository.list_for(request.permission, request.tenant_id):
            if isinstance(rule, MinimumAssuranceConstraint):
                violation = self._evaluate_assurance(rule, request)
                if violation is not None:
                    return violation
                continue
            if request.resource is None:
                return GovernanceViolation(
                    GovernanceViolationKind.CONSTRAINT_CONTEXT_MISSING,
                    rule.id,
                    "resource is required by authorization constraint",
                )
            raw = request.resource.attributes.get(rule.resource_attribute, _MISSING)
            if raw is _MISSING:
                return GovernanceViolation(
                    GovernanceViolationKind.CONSTRAINT_CONTEXT_MISSING,
                    rule.id,
                    f"missing resource attribute {rule.resource_attribute}",
                )
            if isinstance(rule, NumericMaximumConstraint):
                violation = self._evaluate_numeric(rule, raw)
                if violation is not None:
                    return violation
            elif str(raw) != rule.expected_value:
                return GovernanceViolation(
                    GovernanceViolationKind.CONSTRAINT_VIOLATION,
                    rule.id,
                    f"{rule.resource_attribute} does not match required value",
                )
        return None

    @staticmethod
    def _evaluate_assurance(
        rule: MinimumAssuranceConstraint,
        request: AuthorizationRequest,
    ) -> GovernanceViolation | None:
        evidence = request.authentication
        if evidence is None:
            return GovernanceViolation(
                GovernanceViolationKind.AUTHENTICATION_CONTEXT_MISSING,
                rule.id,
                "authentication evidence is required by minimum assurance constraint",
                required_assurance_level=rule.minimum_assurance,
                required_mfa=rule.require_mfa,
            )
        if (
            _assurance_rank(evidence.assurance_level)
            < _assurance_rank(rule.minimum_assurance)
            or (rule.require_mfa and not evidence.mfa)
        ):
            return GovernanceViolation(
                GovernanceViolationKind.ASSURANCE_STEP_UP_REQUIRED,
                rule.id,
                "authentication assurance does not satisfy the configured minimum",
                required_assurance_level=rule.minimum_assurance,
                required_mfa=rule.require_mfa,
            )
        return None

    @staticmethod
    def _evaluate_numeric(
        rule: NumericMaximumConstraint,
        raw: object,
    ) -> GovernanceViolation | None:
        if isinstance(raw, bool):
            return GovernanceViolation(
                GovernanceViolationKind.CONSTRAINT_CONTEXT_MISSING,
                rule.id,
                f"resource attribute {rule.resource_attribute} is not numeric",
            )
        try:
            value = Decimal(str(raw))
            exceeded = value > rule.maximum
        except InvalidOperation:
            return GovernanceViolation(
                GovernanceViolationKind.CONSTRAINT_CONTEXT_MISSING,
                rule.id,
                f"resource attribute {rule.resource_attribute} is not numeric",
            )
        if exceeded:
            return GovernanceViolation(
                GovernanceViolationKind.CONSTRAINT_VIOLATION,
                rule.id,
                f"{rule.resource_attribute} exceeds configured maximum",
            )
        return None


class DynamicSoDEvaluator:
    def __init__(self, repository: SoDRuleRepository) -> None:
        self._repository = repository

    def evaluate(self, request: AuthorizationRequest) -> GovernanceViolation | None:
        for rule in self._repository.list_dynamic(request.permission, request.tenant_id):
            if request.resource is None:
                return GovernanceViolation(
                    GovernanceViolationKind.SOD_CONTEXT_MISSING,
                    rule.id,
                    "resource is required by dynamic SoD rule",
                )
            actor = request.resource.attributes.get(rule.resource_attribute, _MISSING)
            if actor is _MISSING:
                return GovernanceViolation(
                    GovernanceViolationKind.SOD_CONTEXT_MISSING,
                    rule.id,
                    f"missing resource actor attribute {rule.resource_attribute}",
                )
            if actor == request.subject_id or str(actor) == str(request.subject_id):
                return GovernanceViolation(
                    GovernanceViolationKind.SOD_DYNAMIC_CONFLICT,
                    rule.id,
                    f"subject matches prohibited actor attribute {rule.resource_attribute}",
                )
        return None


class StaticSoDEvaluator:
    """Evaluate mutually exclusive effective Roles, including inherited Roles."""

    def __init__(
        self,
        *,
        role_repository: RoleRepository,
        sod_repository: SoDRuleRepository,
        max_hierarchy_depth: int = 32,
    ) -> None:
        self._sod = sod_repository
        self._hierarchy = RoleHierarchyResolver(
            role_repository,
            max_depth=max_hierarchy_depth,
        )

    def ensure_assignment_allowed(
        self,
        *,
        candidate_role_id: RoleId,
        existing_bindings: tuple[RoleBinding, ...],
        tenant_id: TenantId,
    ) -> None:
        try:
            effective_ids = self._effective_role_ids(existing_bindings)
            effective_ids.update(
                role.id for role in self._hierarchy.resolve_roles(candidate_role_id)
            )
        except RoleHierarchyError as exc:
            raise StaticSoDViolation(candidate_role_id) from exc
        violation = self._find_conflict(effective_ids, tenant_id)
        if violation is not None:
            raise StaticSoDViolation(violation.rule_id)

    def detect_runtime(
        self,
        *,
        bindings: tuple[RoleBinding, ...],
        tenant_id: TenantId,
    ) -> GovernanceViolation | None:
        rules = self._sod.list_static(tenant_id)
        if not rules:
            return None
        try:
            effective_ids = self._effective_role_ids(bindings)
        except RoleHierarchyError as exc:
            return GovernanceViolation(
                GovernanceViolationKind.SOD_STATIC_CONFLICT,
                rules[0].id,
                f"static SoD cannot be evaluated safely: {exc.code}",
            )
        return self._find_conflict(effective_ids, tenant_id)

    def _effective_role_ids(self, bindings: tuple[RoleBinding, ...]) -> set[RoleId]:
        effective: set[RoleId] = set()
        for binding in bindings:
            effective.update(role.id for role in self._hierarchy.resolve_roles(binding.role_id))
        return effective

    def _find_conflict(
        self,
        effective_role_ids: set[RoleId],
        tenant_id: TenantId,
    ) -> GovernanceViolation | None:
        for rule in self._sod.list_static(tenant_id):
            if (
                rule.first_role_id in effective_role_ids
                and rule.second_role_id in effective_role_ids
            ):
                return GovernanceViolation(
                    GovernanceViolationKind.SOD_STATIC_CONFLICT,
                    rule.id,
                    "mutually exclusive effective Roles are simultaneously active",
                )
        return None


def _assurance_rank(level: AssuranceLevel) -> int:
    return {
        AssuranceLevel.AAL1: 1,
        AssuranceLevel.AAL2: 2,
        AssuranceLevel.AAL3: 3,
    }[level]
