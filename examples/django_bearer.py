from datetime import UTC, datetime, timedelta
from secrets import token_bytes

import django
from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.test import RequestFactory

from pyiamkit.authentication import (
    AssuranceLevel,
    AuthenticationContext,
    AuthenticationMethod,
    Session,
)
from pyiamkit.authentication.adapters import InMemorySessionRepository
from pyiamkit.authentication.adapters.jwt import JwtTokenProvider
from pyiamkit.identity import IdentityId
from pyiamkit.integrations.django import bearer_required, get_authenticated_claims

if not settings.configured:
    settings.configure(
        SECRET_KEY="pyiamkit-example",
        DEFAULT_CHARSET="utf-8",
        ALLOWED_HOSTS=["testserver"],
        USE_TZ=True,
    )
    django.setup()


class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


now = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)
clock = FrozenClock(now)
sessions = InMemorySessionRepository()

session = Session.open(
    identity_id=IdentityId.new(),
    context=AuthenticationContext(
        method=AuthenticationMethod.PASSKEY,
        assurance_level=AssuranceLevel.AAL2,
        mfa=True,
        authenticated_at=now,
    ),
    created_at=now,
    expires_at=now + timedelta(hours=1),
)
session.pull_events()
sessions.save(session)

tokens = JwtTokenProvider(
    issuer="https://iam.example.com",
    audience="api://django",
    signing_key=token_bytes(32),
    session_repository=sessions,
    clock=clock,
    algorithm="HS256",
    leeway=timedelta(0),
)
access_token = tokens.issue_access_token(session).token


@bearer_required(tokens)
def protected(request: HttpRequest) -> JsonResponse:
    claims = get_authenticated_claims(request)
    assert claims is not None
    return JsonResponse({"subject": str(claims.subject_id)})


request = RequestFactory().get(
    "/protected",
    HTTP_AUTHORIZATION=f"Bearer {access_token}",
)
response = protected(request)

assert response.status_code == 200
print("Django Bearer integration OK:", response.status_code)
