"""Reusable Authentication, TokenProvider and SecretStore conformance suites."""

from collections.abc import Callable
from dataclasses import dataclass

from pyiamkit.authentication import (
    AccessTokenClaims,
    AuthenticationSubjectInactive,
    InvalidAccessToken,
    IssuedAccessToken,
    Session,
    SessionStatus,
)

from .report import ConformanceCheck, ConformanceReport


@dataclass(frozen=True, slots=True)
class AuthenticationProbe:
    """Scenario callbacks used to qualify Authentication lifecycle semantics."""

    name: str
    open_active_session: Callable[[], Session]
    open_for_inactive_subject: Callable[[], None]
    revoke_session: Callable[[], Session]
    expire_session: Callable[[], Session]
    revoke_all_sessions: Callable[[], tuple[tuple[Session, ...], tuple[Session, ...]]]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("AuthenticationProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class AuthenticationConformance:
    """Qualify Session lifecycle and inactive-subject fail-closed behavior."""

    suite_name = "AuthenticationConformance"

    def __init__(self, probe: AuthenticationProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("active_subject_opens_session", self._active_subject_opens_session),
                self._check(
                    "inactive_subject_cannot_open_session",
                    self._inactive_subject_cannot_open_session,
                ),
                self._check("revoked_session_is_inactive", self._revoked_session_is_inactive),
                self._check("expired_session_is_inactive", self._expired_session_is_inactive),
                self._check(
                    "bulk_revocation_leaves_no_active_session",
                    self._bulk_revocation_leaves_no_active_session,
                ),
            ),
        )

    def _active_subject_opens_session(self) -> None:
        session = self._probe.open_active_session()
        if session.status is not SessionStatus.ACTIVE:
            raise AssertionError(f"expected active Session, got {session.status.value}")
        if not session.is_active(at=session.created_at):
            raise AssertionError("new Session is not active at creation time")

    def _inactive_subject_cannot_open_session(self) -> None:
        try:
            self._probe.open_for_inactive_subject()
        except AuthenticationSubjectInactive:
            return
        raise AssertionError("inactive subject opened an Authentication Session")

    def _revoked_session_is_inactive(self) -> None:
        session = self._probe.revoke_session()
        if session.status is not SessionStatus.REVOKED:
            raise AssertionError(f"expected revoked Session, got {session.status.value}")
        if session.is_active(at=session.updated_at):
            raise AssertionError("revoked Session remains active")

    def _expired_session_is_inactive(self) -> None:
        session = self._probe.expire_session()
        if session.status is not SessionStatus.EXPIRED:
            raise AssertionError(f"expected expired Session, got {session.status.value}")
        if session.is_active(at=session.updated_at):
            raise AssertionError("expired Session remains active")

    def _bulk_revocation_leaves_no_active_session(self) -> None:
        revoked, active_after = self._probe.revoke_all_sessions()
        if not revoked:
            raise AssertionError("bulk revocation scenario revoked no Sessions")
        if any(session.status is not SessionStatus.REVOKED for session in revoked):
            raise AssertionError("bulk revocation returned a non-revoked Session")
        if active_after:
            raise AssertionError("active Sessions remain after bulk revocation")

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)


@dataclass(frozen=True, slots=True)
class TokenProviderProbe:
    """Scenario callbacks used to qualify access-token provider semantics."""

    name: str
    valid_round_trip: Callable[[], tuple[IssuedAccessToken, AccessTokenClaims]]
    tampered_token: Callable[[], None]
    expired_token: Callable[[], None]
    wrong_trust_context: Callable[[], None]
    revoked_session_token: Callable[[], None]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("TokenProviderProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class TokenProviderConformance:
    """Qualify core access-token trust and Session-authority semantics."""

    suite_name = "TokenProviderConformance"

    def __init__(self, probe: TokenProviderProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("issued_token_round_trips", self._issued_token_round_trips),
                self._check("tampered_token_rejected", self._tampered_token_rejected),
                self._check("expired_token_rejected", self._expired_token_rejected),
                self._check(
                    "wrong_issuer_or_audience_rejected",
                    self._wrong_trust_context_rejected,
                ),
                self._check(
                    "revoked_session_token_rejected",
                    self._revoked_session_token_rejected,
                ),
            ),
        )

    def _issued_token_round_trips(self) -> None:
        issued, verified = self._probe.valid_round_trip()
        if not issued.token.strip():
            raise AssertionError("TokenProvider returned an empty token")
        if verified != issued.claims:
            raise AssertionError("verified claims differ from issued claims")

    def _tampered_token_rejected(self) -> None:
        self._require_invalid(self._probe.tampered_token, "tampered token")

    def _expired_token_rejected(self) -> None:
        self._require_invalid(self._probe.expired_token, "expired token")

    def _wrong_trust_context_rejected(self) -> None:
        self._require_invalid(self._probe.wrong_trust_context, "wrong issuer/audience token")

    def _revoked_session_token_rejected(self) -> None:
        self._require_invalid(self._probe.revoked_session_token, "revoked Session token")

    @staticmethod
    def _require_invalid(operation: Callable[[], None], scenario: str) -> None:
        try:
            operation()
        except InvalidAccessToken:
            return
        raise AssertionError(f"{scenario} was accepted")

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)


@dataclass(frozen=True, slots=True)
class SecretStoreProbe:
    """Callbacks used to qualify secret-reference storage semantics."""

    name: str
    put: Callable[[str, str], None]
    get: Callable[[str], str | None]
    delete: Callable[[str], None]
    reference: Callable[[], str]
    secret: Callable[[], str]

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("SecretStoreProbe.name must not be empty")
        object.__setattr__(self, "name", name)


class SecretStoreConformance:
    """Qualify basic secret-reference confidentiality boundary semantics."""

    suite_name = "SecretStoreConformance"

    def __init__(self, probe: SecretStoreProbe) -> None:
        self._probe = probe

    def run(self) -> ConformanceReport:
        return ConformanceReport(
            suite=self.suite_name,
            target=self._probe.name,
            checks=(
                self._check("missing_reference_returns_none", self._missing_reference_returns_none),
                self._check("put_get_round_trip", self._put_get_round_trip),
                self._check("duplicate_reference_rejected", self._duplicate_reference_rejected),
                self._check("delete_removes_secret", self._delete_removes_secret),
                self._check("delete_missing_is_idempotent", self._delete_missing_is_idempotent),
            ),
        )

    def _missing_reference_returns_none(self) -> None:
        if self._probe.get(self._probe.reference()) is not None:
            raise AssertionError("missing secret reference returned material")

    def _put_get_round_trip(self) -> None:
        reference = self._probe.reference()
        secret = self._probe.secret()
        self._probe.put(reference, secret)
        if self._probe.get(reference) != secret:
            raise AssertionError("stored secret did not round-trip")

    def _duplicate_reference_rejected(self) -> None:
        reference = self._probe.reference()
        self._probe.put(reference, self._probe.secret())
        try:
            self._probe.put(reference, self._probe.secret())
        except ValueError:
            return
        raise AssertionError("duplicate secret reference was overwritten")

    def _delete_removes_secret(self) -> None:
        reference = self._probe.reference()
        self._probe.put(reference, self._probe.secret())
        self._probe.delete(reference)
        if self._probe.get(reference) is not None:
            raise AssertionError("deleted secret remains retrievable")

    def _delete_missing_is_idempotent(self) -> None:
        reference = self._probe.reference()
        self._probe.delete(reference)
        self._probe.delete(reference)
        if self._probe.get(reference) is not None:
            raise AssertionError("missing delete created secret material")

    @staticmethod
    def _check(name: str, operation: Callable[[], None]) -> ConformanceCheck:
        try:
            operation()
        except Exception as exc:
            return ConformanceCheck(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        return ConformanceCheck(name=name, passed=True)
