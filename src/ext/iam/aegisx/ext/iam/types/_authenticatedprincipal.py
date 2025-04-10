from ._anonymousprincipal import AnonymousPrincipal


class AuthenticatedPrincipal(AnonymousPrincipal):
    """Represents an authenticated principal (e.g., all authenticated users).

    This class extends :class:`AnonymousPrincipal` to represent a principal that
    refers specifically to authenticated users. It is used to grant access
    to resources or actions that require user authentication.

    Attributes:
        name (str): The name of the principal.
        description (str): A description of the principal.
        value (str): The unique identifier for the principal, `allAuthenticatedUsers`.
    """
    name = 'All authenticated users'
    description = 'allAuthenticatedUsers'
    constant_value = 'allAuthenticatedUsers'

    def is_authenticated(self) -> bool:
        """Return ``True`` if the principal is authenticated.

        This method always returns ``True`` because the authenticated principal
        is considered authenticated (obviously).

        Returns:
            bool: Always returns ``True``, as the principal is authenticated.
        """
        return True