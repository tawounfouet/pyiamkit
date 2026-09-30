import pytest

from pyiamkit.operations import (
    CacheNamespace,
    InvalidationKind,
    RevocationTargetType,
    SecurityStateStamp,
    StateVersion,
)


def test_state_version_is_immutable_orderable_and_non_negative() -> None:
    initial = StateVersion(0)
    changed = StateVersion(1)

    assert initial.value == 0
    assert initial < changed

    with pytest.raises(ValueError, match="greater than or equal to zero"):
        StateVersion(-1)


@pytest.mark.parametrize("value", [True, 1.5, "1", None])
def test_state_version_rejects_non_integer_values(value: object) -> None:
    with pytest.raises(TypeError, match="must be an integer"):
        StateVersion(value)  # type: ignore[arg-type]


def test_security_state_stamp_preserves_independent_dimensions() -> None:
    stamp = SecurityStateStamp(
        identity=StateVersion(1),
        tenant=StateVersion(2),
        membership=StateVersion(3),
        authorization=StateVersion(4),
        governance=StateVersion(5),
        authentication=StateVersion(6),
    )

    assert stamp.identity == StateVersion(1)
    assert stamp.tenant == StateVersion(2)
    assert stamp.membership == StateVersion(3)
    assert stamp.authorization == StateVersion(4)
    assert stamp.governance == StateVersion(5)
    assert stamp.authentication == StateVersion(6)


def test_security_state_stamp_rejects_untyped_dimensions() -> None:
    with pytest.raises(TypeError, match="identity must be a StateVersion"):
        SecurityStateStamp(
            identity=0,  # type: ignore[arg-type]
            tenant=StateVersion(0),
            membership=StateVersion(0),
            authorization=StateVersion(0),
            governance=StateVersion(0),
            authentication=StateVersion(0),
        )


def test_cache_namespace_is_canonical_and_collision_resistant() -> None:
    namespace = CacheNamespace(
        application=" Billing-API ",
        environment=" PROD ",
        schema_version=2,
    )

    assert namespace.application == "billing-api"
    assert namespace.environment == "prod"
    assert namespace.prefix == "pyiamkit:billing-api:prod:v2"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("application", ""),
        ("application", "billing:api"),
        ("environment", "prod east"),
        ("environment", "{prod}"),
    ],
)
def test_cache_namespace_rejects_invalid_components(field: str, value: str) -> None:
    kwargs = {
        "application": "billing-api",
        "environment": "prod",
    }
    kwargs[field] = value

    with pytest.raises(ValueError):
        CacheNamespace(**kwargs)


@pytest.mark.parametrize("schema_version", [0, -1])
def test_cache_namespace_requires_positive_schema_version(schema_version: int) -> None:
    with pytest.raises(ValueError, match="greater than or equal to one"):
        CacheNamespace("billing-api", "prod", schema_version=schema_version)


@pytest.mark.parametrize("schema_version", [True, 1.5, "1", None])
def test_cache_namespace_rejects_non_integer_schema_version(
    schema_version: object,
) -> None:
    with pytest.raises(TypeError, match="must be an integer"):
        CacheNamespace(
            "billing-api",
            "prod",
            schema_version=schema_version,  # type: ignore[arg-type]
        )


def test_operational_enums_have_stable_wire_values() -> None:
    assert RevocationTargetType.SESSION.value == "session"
    assert RevocationTargetType.IDENTITY.value == "identity"
    assert RevocationTargetType.MEMBERSHIP.value == "membership"
    assert RevocationTargetType.ROLE_BINDING.value == "role_binding"
    assert RevocationTargetType.TENANT.value == "tenant"

    assert InvalidationKind.IDENTITY.value == "identity"
    assert InvalidationKind.TENANT.value == "tenant"
    assert InvalidationKind.MEMBERSHIP.value == "membership"
    assert InvalidationKind.AUTHORIZATION.value == "authorization"
    assert InvalidationKind.GOVERNANCE.value == "governance"
    assert InvalidationKind.AUTHENTICATION.value == "authentication"
