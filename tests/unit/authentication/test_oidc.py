from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import jwt as pyjwt
import pytest

from pyiamkit.authentication import AssuranceLevel, InvalidIdentityToken
from pyiamkit.authentication.adapters.oidc import (
    OidcConfigurationError,
    StaticOidcAssuranceResolver,
    StaticOidcIdTokenVerifier,
)

NOW = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
ISSUER = "https://login.example.com/tenant/v2.0"
CLIENT_ID = "client-123"


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "iss": ISSUER,
        "sub": "subject-42",
        "aud": CLIENT_ID,
        "exp": int((NOW + timedelta(minutes=10)).timestamp()),
        "iat": int(NOW.timestamp()),
        "auth_time": int((NOW - timedelta(minutes=1)).timestamp()),
        "nonce": "nonce-123",
        "acr": "urn:example:aal2",
        "amr": ["pwd", "mfa"],
        "email": "alice@example.com",
        "email_verified": True,
    }
    payload.update(overrides)
    return payload


def _token(
    key: bytes,
    *,
    payload: dict[str, object] | None = None,
    algorithm: str = "HS256",
    key_id: str | None = None,
) -> str:
    headers = {"typ": "JWT"}
    if key_id is not None:
        headers["kid"] = key_id
    return pyjwt.encode(
        _payload() if payload is None else payload,
        key,
        algorithm=algorithm,
        headers=headers,
    )


def _verifier(
    key: bytes,
    *,
    clock: FrozenClock | None = None,
) -> StaticOidcIdTokenVerifier:
    return StaticOidcIdTokenVerifier(
        provider_id="entra-prod",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        verification_key=key,
        algorithm="HS256",
        clock=clock or FrozenClock(NOW),
        leeway=timedelta(0),
    )


def test_oidc_verifier_validates_signature_registered_claims_and_nonce() -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    claims = verifier.verify_identity_token(
        _token(key),
        expected_nonce="nonce-123",
    )

    assert claims.provider_id == "entra-prod"
    assert claims.issuer == ISSUER
    assert claims.subject == "subject-42"
    assert claims.audiences == (CLIENT_ID,)
    assert claims.nonce == "nonce-123"
    assert claims.acr == "urn:example:aal2"
    assert claims.amr == ("pwd", "mfa")
    assert claims.email == "alice@example.com"
    assert claims.email_verified is True


@pytest.mark.parametrize(
    "payload",
    [
        _payload(iss="https://other.example.com"),
        _payload(aud="other-client"),
    ],
)
def test_wrong_issuer_or_audience_is_rejected(payload: dict[str, object]) -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    with pytest.raises(InvalidIdentityToken):
        verifier.verify_identity_token(_token(key, payload=payload))


@pytest.mark.parametrize(
    "payload",
    [
        _payload(nonce=None),
        _payload(nonce="other-nonce"),
    ],
)
def test_expected_nonce_must_be_present_and_equal(payload: dict[str, object]) -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    with pytest.raises(InvalidIdentityToken, match="nonce"):
        verifier.verify_identity_token(
            _token(key, payload=payload),
            expected_nonce="nonce-123",
        )


def test_multiple_audiences_require_matching_authorized_party() -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    missing_azp = _payload(aud=[CLIENT_ID, "other-client"])
    wrong_azp = _payload(aud=[CLIENT_ID, "other-client"], azp="other-client")
    valid = _payload(aud=[CLIENT_ID, "other-client"], azp=CLIENT_ID)

    with pytest.raises(InvalidIdentityToken, match="azp"):
        verifier.verify_identity_token(_token(key, payload=missing_azp))
    with pytest.raises(InvalidIdentityToken, match="azp"):
        verifier.verify_identity_token(_token(key, payload=wrong_azp))

    claims = verifier.verify_identity_token(_token(key, payload=valid))
    assert claims.authorized_party == CLIENT_ID


def test_expired_or_future_issued_id_token_is_rejected_by_injected_clock() -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    expired = _payload(
        iat=int((NOW - timedelta(minutes=20)).timestamp()),
        exp=int((NOW - timedelta(minutes=1)).timestamp()),
        auth_time=int((NOW - timedelta(minutes=21)).timestamp()),
    )
    future = _payload(
        iat=int((NOW + timedelta(minutes=1)).timestamp()),
        exp=int((NOW + timedelta(minutes=10)).timestamp()),
        auth_time=int(NOW.timestamp()),
    )

    with pytest.raises(InvalidIdentityToken, match="expired"):
        verifier.verify_identity_token(_token(key, payload=expired))
    with pytest.raises(InvalidIdentityToken, match="future"):
        verifier.verify_identity_token(_token(key, payload=future))


def test_algorithm_is_fixed_by_configuration_not_selected_by_token_header() -> None:
    key = token_bytes(48)
    verifier = _verifier(key)
    token = _token(key, algorithm="HS384")

    with pytest.raises(InvalidIdentityToken, match="algorithm"):
        verifier.verify_identity_token(token)


def test_configured_key_set_requires_known_kid() -> None:
    key = token_bytes(32)
    verifier = StaticOidcIdTokenVerifier(
        provider_id="entra-prod",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        verification_keys={"current": key},
        algorithm="HS256",
        clock=FrozenClock(NOW),
        leeway=timedelta(0),
    )

    with pytest.raises(InvalidIdentityToken, match="required"):
        verifier.verify_identity_token(_token(key))
    with pytest.raises(InvalidIdentityToken, match="unknown"):
        verifier.verify_identity_token(_token(key, key_id="unknown"))

    claims = verifier.verify_identity_token(_token(key, key_id="current"))
    assert claims.subject == "subject-42"


def test_oidc_assurance_mapping_is_explicit_and_provider_configured() -> None:
    key = token_bytes(32)
    claims = _verifier(key).verify_identity_token(_token(key))
    resolver = StaticOidcAssuranceResolver(
        acr_mapping={"urn:example:aal2": AssuranceLevel.AAL2},
        mfa_amr_values=("mfa", "otp"),
    )

    assurance = resolver.resolve(claims)

    assert assurance.level is AssuranceLevel.AAL2
    assert assurance.mfa is True


@pytest.mark.parametrize(
    "issuer",
    [
        "http://login.example.com",
        "https://login.example.com?tenant=1",
        "https://login.example.com#fragment",
        "",
    ],
)
def test_oidc_configuration_rejects_invalid_issuer(issuer: str) -> None:
    with pytest.raises(OidcConfigurationError):
        StaticOidcIdTokenVerifier(
            provider_id="entra-prod",
            issuer=issuer,
            client_id=CLIENT_ID,
            verification_key=token_bytes(32),
            algorithm="HS256",
            clock=FrozenClock(NOW),
        )


def test_subject_must_be_nonempty_ascii_and_at_most_255_bytes() -> None:
    key = token_bytes(32)
    verifier = _verifier(key)

    for subject in ("", "é", "a" * 256):
        with pytest.raises(InvalidIdentityToken):
            verifier.verify_identity_token(
                _token(key, payload=_payload(sub=subject))
            )
