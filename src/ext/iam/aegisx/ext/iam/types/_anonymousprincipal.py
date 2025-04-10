from typing import Self

from ._principal import Principal


class AnonymousPrincipal(Principal[str]):
    """Represents an anonymous principal (e.g., all users).

    This class represents a special type of principal that refers to all
    users in a system, typically used to grant access to resources or
    actions that are available to everyone, whether authenticated or not.

    Attributes:
        kind (str): The kind of principal. In this case, it's an empty string.
        name (str): The name of the principal, 'All users'.
        description (str): A description of the principal, 'All users'.
        value (str): The unique identifier for the principal, 'allUsers'.
    """
    kind: str = ''
    name = 'All users'
    description = 'All users'
    constant_value = 'allUsers'

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validate the value of the anonymous principal.

        This method ensures that the value matches the predefined value for
        an anonymous principal (`allUsers`). If the value does not match, 
        a :exc:`ValueError` is raised.

        Args:
            value (str): The value to be validated.

        Returns:
            An instance of `AnonymousPrincipal` if validation passes.

        Raises:
            ValueError: If the value does not match `allUsers`.
        """
        if value != cls.constant_value:
            raise ValueError(f'not an {cls.__name__}: {value}.')
        return cls(value=value)

    def is_authenticated(self) -> bool:
        """Return ``True`` if the principal is authenticated.

        This method always returns ``False`` because the anonymous principal
        is not authenticated.

        Returns:
            bool: Always returns ``False``, as the anonymous principal is
                not authenticated.
        """
        return False

    def is_subject(self) -> bool:
        """Return ``True`` if the principal resolves to a single subject.

        This method always returns ``True`` because the anonymous principal
        is considered a single subject.

        Returns:
            bool: Always returns ``True``, as the anonymous principal is
                treated as a single subject.
        """
        return True

    def __hash__(self):
        return hash(self._value)