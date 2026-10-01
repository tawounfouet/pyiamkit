"""Distributed authorization orchestration over authoritative IAM semantics."""

from datetime import datetime, timedelta

from pyiamkit.authorization import (
    AuthorizationDecision,
    AuthorizationDenied,
    AuthorizationEngine,
    AuthorizationReason,
    AuthorizationRequest,
    AuthorizationResult,
    DecisionExplanation,
    ExplanationLevel,
)
from pyiamkit.shared import Clock

from .cache import (
    AuthorizationCacheEntry,
    AuthorizationCacheKey,
    CachedAuthorizationDecision,
)
from .errors import AuthorizationRuntimeUnavailable, RevocationRegistryUnavailable
from .ports import AuthorizationCache, RevocationRegistry, SecurityStateReader
from .revocation import RevocationMarker, RevocationTargetType
from .state import SecurityStateStamp, StateVersion


class DistributedAuthorizationRuntime:
    """Coordinate revocation, state stamps, cache and authoritative authorization."""

    def __init__(
        self,
        *,
        engine: AuthorizationEngine,
        security_state: SecurityStateReader,
        cache: AuthorizationCache,
        revocations: RevocationRegistry,
        clock: Clock,
        cache_ttl: timedelta = timedelta(seconds=30),
        max_state_retries: int = 1,
    ) -> None:
        if cache_ttl <= timedelta(0):
            raise ValueError("cache_ttl must be positive")
        if isinstance(max_state_retries, bool) or not isinstance(max_state_retries, int):
            raise TypeError("max_state_retries must be an integer")
        if max_state_retries < 0:
            raise ValueError("max_state_retries must be greater than or equal to zero")
        self._engine = engine
        self._security_state = security_state
        self._cache = cache
        self._revocations = revocations
        self._clock = clock
        self._cache_ttl = cache_ttl
        self._max_state_retries = max_state_retries

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        key = AuthorizationCacheKey.from_request(request)

        for _ in range(self._max_state_retries + 1):
            now = self._clock.now()
            before = self._stamp(request)
            revocations_available = True

            try:
                revoked = self._request_revocation(request, before, at=now)
            except RevocationRegistryUnavailable:
                revocations_available = False
                revoked = None
                self._cache.delete(key)
            if revoked is not None:
                self._cache.delete(key)
                return self._record(self._revocation_denial(request, revoked, at=now))

            if revocations_available:
                cached = self._cache.get(key, current_state=before, at=now)
                if cached is not None:
                    after = self._stamp(request)
                    if after != before:
                        continue
                    try:
                        revoked = self._cached_revocation(cached, after, at=now)
                        if revoked is None:
                            revoked = self._request_revocation(request, after, at=now)
                    except RevocationRegistryUnavailable:
                        revocations_available = False
                        self._cache.delete(key)
                    else:
                        if revoked is not None:
                            self._cache.delete(key)
                            return self._record(
                                self._revocation_denial(request, revoked, at=now)
                            )
                        return self._record(
                            cached.decision.to_decision(request, evaluated_at=now)
                        )

            decision = self._engine.authorize(request)
            after = self._stamp(request)
            if after != before:
                self._cache.delete(key)
                continue

            revoked = None
            if revocations_available:
                try:
                    revoked = self._request_revocation(request, after, at=now)
                    if revoked is None and decision.allowed:
                        revoked = self._decision_revocation(decision, after, at=now)
                except RevocationRegistryUnavailable:
                    revocations_available = False
                    self._cache.delete(key)

            if revoked is not None:
                self._cache.delete(key)
                return self._record(self._revocation_denial(request, revoked, at=now))

            if decision.allowed and revocations_available:
                self._cache_allow(key, decision, after, at=now)
            return decision

        raise AuthorizationRuntimeUnavailable(
            "Authorization state changed during evaluation and did not stabilize."
        )

    def can(self, request: AuthorizationRequest) -> bool:
        return self.authorize(request).allowed

    def require(self, request: AuthorizationRequest) -> AuthorizationDecision:
        decision = self.authorize(request)
        if not decision.allowed:
            raise AuthorizationDenied(decision)
        return decision

    def explain(self, request: AuthorizationRequest) -> AuthorizationDecision:
        return self.authorize(request)

    def describe(
        self,
        request: AuthorizationRequest,
        *,
        level: ExplanationLevel = ExplanationLevel.SUMMARY,
    ) -> DecisionExplanation:
        return self.authorize(request).explanation(level)

    def _stamp(self, request: AuthorizationRequest) -> SecurityStateStamp:
        return self._security_state.stamp_for(
            identity_id=request.subject_id,
            tenant_id=request.tenant_id,
        )

    def _request_revocation(
        self,
        request: AuthorizationRequest,
        stamp: SecurityStateStamp,
        *,
        at: datetime,
    ) -> RevocationMarker | None:
        marker = self._active_marker(
            RevocationTargetType.IDENTITY,
            str(request.subject_id),
            current_version=stamp.identity,
            at=at,
        )
        if marker is not None:
            return marker
        return self._active_marker(
            RevocationTargetType.TENANT,
            str(request.tenant_id),
            current_version=stamp.tenant,
            at=at,
        )

    def _cached_revocation(
        self,
        entry: AuthorizationCacheEntry,
        stamp: SecurityStateStamp,
        *,
        at: datetime,
    ) -> RevocationMarker | None:
        return self._semantic_revocation(entry.decision, stamp, at=at)

    def _decision_revocation(
        self,
        decision: AuthorizationDecision,
        stamp: SecurityStateStamp,
        *,
        at: datetime,
    ) -> RevocationMarker | None:
        return self._semantic_revocation(
            CachedAuthorizationDecision.from_decision(decision),
            stamp,
            at=at,
        )

    def _semantic_revocation(
        self,
        decision: CachedAuthorizationDecision,
        stamp: SecurityStateStamp,
        *,
        at: datetime,
    ) -> RevocationMarker | None:
        if decision.matched_membership_id is not None:
            marker = self._active_marker(
                RevocationTargetType.MEMBERSHIP,
                str(decision.matched_membership_id),
                current_version=stamp.membership,
                at=at,
            )
            if marker is not None:
                return marker
        if decision.matched_binding_id is not None:
            return self._active_marker(
                RevocationTargetType.ROLE_BINDING,
                str(decision.matched_binding_id),
                current_version=stamp.subject_authorization,
                at=at,
            )
        return None

    def _active_marker(
        self,
        target_type: RevocationTargetType,
        target_id: str,
        *,
        current_version: StateVersion,
        at: datetime,
    ) -> RevocationMarker | None:
        marker = self._revocations.get(target_type, target_id)
        if marker is None:
            return None
        if not marker.is_active(at=at):
            return None
        if not marker.applies_to(current_version):
            return None
        return marker

    def _cache_allow(
        self,
        key: AuthorizationCacheKey,
        decision: AuthorizationDecision,
        stamp: SecurityStateStamp,
        *,
        at: datetime,
    ) -> None:
        expires_at = at + self._cache_ttl
        if decision.valid_until is not None and decision.valid_until < expires_at:
            expires_at = decision.valid_until
        if expires_at <= at:
            return
        self._cache.put(
            AuthorizationCacheEntry(
                key=key,
                decision=CachedAuthorizationDecision.from_decision(decision),
                state_stamp=stamp,
                cached_at=at,
                expires_at=expires_at,
            )
        )

    def _revocation_denial(
        self,
        request: AuthorizationRequest,
        marker: RevocationMarker,
        *,
        at: datetime,
    ) -> AuthorizationDecision:
        reasons = {
            RevocationTargetType.IDENTITY: AuthorizationReason.DENY_SUBJECT_INACTIVE,
            RevocationTargetType.TENANT: AuthorizationReason.DENY_TENANT_INACTIVE,
            RevocationTargetType.MEMBERSHIP: AuthorizationReason.DENY_MEMBERSHIP_NOT_FOUND,
            RevocationTargetType.ROLE_BINDING: AuthorizationReason.DENY_NO_ACTIVE_BINDING,
            RevocationTargetType.SESSION: AuthorizationReason.DENY_AUTHENTICATION_CONTEXT_MISSING,
        }
        reason = reasons[marker.target_type]
        return AuthorizationDecision(
            result=AuthorizationResult.DENY,
            reason_code=reason,
            subject_id=request.subject_id,
            tenant_id=request.tenant_id,
            permission=request.permission,
            scope=request.scope,
            evaluated_at=at,
            resource=request.resource,
            correlation_id=request.correlation_id,
            explanation_path=(
                f"revocation:{marker.target_type.value}:{marker.target_id}",
                f"revocation_reason:{marker.reason_code}",
                reason.value,
                AuthorizationResult.DENY.value,
            ),
        )

    def _record(self, decision: AuthorizationDecision) -> AuthorizationDecision:
        return self._engine.record_decision(decision)
