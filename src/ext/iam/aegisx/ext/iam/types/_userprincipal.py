from typing import Self

from libcanonical.types import EmailAddress

from ._domainprincipal import DomainPrincipal
from ._principal import Principal


class UserPrincipal(Principal[EmailAddress]):
    """Represents a user principal identified by an email address.

    This class represents a user principal, which is identified by an email
    address. It validates and parses a string in the format ``user:USER_EMAIL_ADDRESS``,
    where ``USER_EMAIL_ADDRESS`` is an email address. This principal is typically
    used to represent specific users in the system.
    """
    kind = 'user'
    name = 'User'
    description = (
        'user:USER_EMAIL_ADDRESS\n\n'
        'Example: user:alex@example.com'
    )

    @property
    def domain(self): # pragma: no cover
        return DomainPrincipal(self.value.domain)

    @classmethod
    def fromemail(cls, value: str):
        return cls.validate(f'{cls.kind}:{value}')

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validate and parse the provided value as a `UserPrincipal`.

        This method parses the string to ensure it is in the format
        ``user:USER_EMAIL_ADDRESS``. It extracts the email address and
        validates that it matches the expected structure of a user principal.

        Args:
            value (str): The string to be validated and parsed. It should be
                in the format ``user:USER_EMAIL_ADDRESS``.

        Raises:
            ValueError: If the provided value is malformed or does not match
                the expected format.

        Returns:
            UserPrincipal
        """
        try:
            kind, value = str.split(value, ':')
        except ValueError:
            raise ValueError('malformed principal.')
        if kind != cls.kind:
            raise ValueError(f'not a {cls.__name__}.')
        return cls(value=EmailAddress.fromstring(value))

    def is_authenticated(self) -> bool:
        """Return ``True`` if the principal is authenticated.

        This method always returns ``True`` because a user principal is
        considered authenticated.

        Returns:
            bool: Always returns ``True``, as the principal is authenticated.
        """
        return True

    def is_subject(self) -> bool:
        """Return ``True`` if the principal resolves to a single subject.

        This method returns ``True`` because a user principal resolves to
        a specific user, i.e., a single subject.

        Returns:
            bool: Always returns ``True``, as the principal resolves to a
                single subject (the user).
        """
        return True

    def __hash__(self) -> int:
        return hash(str(self))