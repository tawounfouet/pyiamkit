"""PyOTP-backed TOTP adapter with external secret storage."""

from datetime import datetime

import pyotp

from ..domain.errors import MfaSecretUnavailable
from ..domain.value_objects import MfaFactorId
from ..mfa import MfaSecretStore, TotpEnrollmentMaterial


class InMemoryMfaSecretStore:
    """Reference secret store for tests/examples only."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def put(self, reference: str, secret: str) -> None:
        normalized = reference.strip()
        if not normalized:
            raise ValueError("reference must not be empty")
        if normalized in self._secrets:
            raise ValueError("secret reference already exists")
        self._secrets[normalized] = secret

    def get(self, reference: str) -> str | None:
        return self._secrets.get(reference.strip())

    def delete(self, reference: str) -> None:
        self._secrets.pop(reference.strip(), None)


class PyOtpTotpProvider:
    """Generate and verify TOTP codes without persisting secret material in factors."""

    def __init__(
        self,
        *,
        secret_store: MfaSecretStore,
        issuer_name: str,
        digits: int = 6,
        interval: int = 30,
        valid_window: int = 1,
    ) -> None:
        issuer = issuer_name.strip()
        if not issuer:
            raise ValueError("issuer_name must not be empty")
        if digits not in {6, 8}:
            raise ValueError("digits must be 6 or 8")
        if interval <= 0:
            raise ValueError("interval must be positive")
        if valid_window < 0:
            raise ValueError("valid_window must not be negative")

        self._secret_store = secret_store
        self._issuer = issuer
        self._digits = digits
        self._interval = interval
        self._valid_window = valid_window

    def begin_enrollment(
        self,
        *,
        factor_id: MfaFactorId,
        account_name: str,
    ) -> TotpEnrollmentMaterial:
        account = account_name.strip()
        if not account:
            raise ValueError("account_name must not be empty")

        reference = f"mfa://totp/{factor_id}"
        secret = pyotp.random_base32()
        self._secret_store.put(reference, secret)
        totp = pyotp.TOTP(
            secret,
            digits=self._digits,
            interval=self._interval,
        )
        return TotpEnrollmentMaterial(
            secret_reference=reference,
            provisioning_uri=totp.provisioning_uri(
                name=account,
                issuer_name=self._issuer,
            ),
        )

    def verify(
        self,
        *,
        secret_reference: str,
        code: str,
        at: datetime,
        minimum_counter_exclusive: int | None,
    ) -> int | None:
        normalized = code.strip()
        if len(normalized) != self._digits or not normalized.isdigit():
            return None

        secret = self._secret_store.get(secret_reference)
        if secret is None:
            raise MfaSecretUnavailable(secret_reference)

        totp = pyotp.TOTP(
            secret,
            digits=self._digits,
            interval=self._interval,
        )
        base_counter = totp.timecode(at)

        for offset in range(-self._valid_window, self._valid_window + 1):
            counter = base_counter + offset
            if counter < 0:
                continue
            if minimum_counter_exclusive is not None and counter <= minimum_counter_exclusive:
                continue
            expected = totp.at(at, counter_offset=offset)
            if pyotp.utils.strings_equal(expected, normalized):
                return counter

        return None

    def delete(self, secret_reference: str) -> None:
        self._secret_store.delete(secret_reference)
