import re
from datetime import UTC, datetime
from secrets import token_bytes

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pyiamkit.authentication import InvalidAccessToken, InvalidIdentityToken
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.authentication.adapters.oidc import StaticOidcIdTokenVerifier
from pyiamkit.authorization import InvalidPermissionCode, PermissionCode
from pyiamkit.provisioning import InvalidScimRequest
from pyiamkit.provisioning.http import parse_scim_user_payload, parse_user_filter_expression
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 3, 8, 30, tzinfo=UTC)
_PERMISSION_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _jwt_provider() -> JwtTokenProvider:
    return JwtTokenProvider(
        issuer="https://issuer.example",
        audience="api://pyiamkit",
        signing_key=token_bytes(32),
        session_repository=InMemorySessionRepository(),
        clock=FrozenClock(),
        algorithm="HS256",
    )


def _oidc_verifier() -> StaticOidcIdTokenVerifier:
    return StaticOidcIdTokenVerifier(
        provider_id="example",
        issuer="https://issuer.example",
        client_id="client-1",
        verification_key=token_bytes(32),
        algorithm="HS256",
        clock=FrozenClock(),
    )


@settings(max_examples=100, deadline=None)
@given(token=st.text(max_size=512))
@pytest.mark.security
def test_fuzz_jwt_adapter_rejects_untrusted_text_without_internal_error(token: str) -> None:
    provider = _jwt_provider()

    with pytest.raises(InvalidAccessToken):
        provider.verify_access_token(token)


@settings(max_examples=100, deadline=None)
@given(token=st.text(max_size=512))
@pytest.mark.security
def test_fuzz_oidc_adapter_rejects_untrusted_text_without_internal_error(token: str) -> None:
    verifier = _oidc_verifier()

    with pytest.raises(InvalidIdentityToken):
        verifier.verify_identity_token(token)


_JSON_SCALAR = st.none() | st.booleans() | st.integers() | st.floats(
    allow_nan=False,
    allow_infinity=False,
) | st.text(max_size=64)
_JSON_VALUE = st.recursive(
    _JSON_SCALAR,
    lambda children: st.lists(children, max_size=5)
    | st.dictionaries(st.text(max_size=32), children, max_size=5),
    max_leaves=20,
)


@settings(max_examples=100, deadline=None)
@given(payload=_JSON_VALUE)
@pytest.mark.security
def test_fuzz_scim_user_payload_fails_with_protocol_error_only(payload: object) -> None:
    try:
        parsed = parse_scim_user_payload(payload)
    except InvalidScimRequest:
        return

    assert parsed.user_name
    if isinstance(payload, dict):
        assert "password" not in payload


@settings(max_examples=100, deadline=None)
@given(filter_expression=st.text(max_size=256))
@pytest.mark.security
def test_fuzz_scim_filter_parser_never_leaks_parser_exceptions(filter_expression: str) -> None:
    try:
        expression = parse_user_filter_expression(filter_expression)
    except InvalidScimRequest:
        return

    if expression is not None:
        assert expression.clauses
        assert all(clause.attribute in {"userName", "externalId"} for clause in expression.clauses)


@settings(max_examples=100, deadline=None)
@given(raw=st.text(max_size=128))
@pytest.mark.security
def test_fuzz_permission_code_is_canonical_or_rejected(raw: str) -> None:
    try:
        permission = PermissionCode(raw)
    except InvalidPermissionCode:
        return

    assert permission.value == raw.strip().lower()
    assert _PERMISSION_PATTERN.fullmatch(permission.value)
