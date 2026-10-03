from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import pytest

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    InvalidAccessToken,
    Session,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.identity import IdentityId
from pyiamkit.shared import Clock

NOW = datetime(2026, 10, 3, 8, 30, tzinfo=UTC)


class FrozenClock(Clock):
    def now(self) -> datetime:
        return NOW


def _session(repository: InMemorySessionRepository) -> Session:
    session = Session.open(
        identity_id=IdentityId.new(),
        context=AuthenticationContext(
            method=AuthenticationMethod.PASSKEY,
            assurance_level=AssuranceLevel.AAL2,
            mfa=True,
            authenticated_at=NOW,
        ),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    session.pull_events()
    repository.save(session)
    return session


def _provider(
    repository: InMemorySessionRepository,
    *,
    signing_key: bytes,
    key_id: str,
    verification_keys: dict[str, bytes],
) -> JwtTokenProvider:
    return JwtTokenProvider(
        issuer="https://issuer.example",
        audience="api://pyiamkit",
        signing_key=signing_key,
        verification_key=signing_key,
        verification_keys=verification_keys,
        key_id=key_id,
        session_repository=repository,
        clock=FrozenClock(),
        algorithm="HS256",
        leeway=timedelta(0),
    )


@pytest.mark.security
def test_jwt_key_rotation_accepts_overlap_then_rejects_retired_key() -> None:
    repository = InMemorySessionRepository()
    session = _session(repository)
    old_key = token_bytes(32)
    new_key = token_bytes(32)

    old_issuer = _provider(
        repository,
        signing_key=old_key,
        key_id="2026-09",
        verification_keys={"2026-09": old_key},
    )
    old_token = old_issuer.issue_access_token(session).token

    overlap = _provider(
        repository,
        signing_key=new_key,
        key_id="2026-10",
        verification_keys={
            "2026-09": old_key,
            "2026-10": new_key,
        },
    )
    new_token = overlap.issue_access_token(session).token

    assert overlap.verify_access_token(old_token).session_id == session.id
    assert overlap.verify_access_token(new_token).session_id == session.id

    retired = _provider(
        repository,
        signing_key=new_key,
        key_id="2026-10",
        verification_keys={"2026-10": new_key},
    )

    with pytest.raises(InvalidAccessToken, match="unknown"):
        retired.verify_access_token(old_token)

    assert retired.verify_access_token(new_token).session_id == session.id


@pytest.mark.security
def test_jwt_rotation_never_falls_back_for_unknown_kid() -> None:
    repository = InMemorySessionRepository()
    session = _session(repository)
    trusted = token_bytes(32)
    untrusted = token_bytes(32)

    attacker = _provider(
        repository,
        signing_key=untrusted,
        key_id="attacker",
        verification_keys={"attacker": untrusted},
    )
    forged = attacker.issue_access_token(session).token

    verifier = _provider(
        repository,
        signing_key=trusted,
        key_id="current",
        verification_keys={"current": trusted},
    )

    with pytest.raises(InvalidAccessToken, match="unknown"):
        verifier.verify_access_token(forged)
