"""Human user profile."""

from dataclasses import dataclass

from ..value_objects.email_address import EmailAddress


@dataclass(frozen=True, slots=True)
class User:
    """Human profile attached to an Identity aggregate."""

    primary_email: EmailAddress | None = None
    email_verified: bool = False
    first_name: str | None = None
    last_name: str | None = None
    locale: str | None = None
    timezone: str | None = None
