from ._userprincipal import UserPrincipal


class ServiceAccountPrincipal(UserPrincipal):
    """Represents a service account principal identified by an email address.

    This class represents a service account principal, which is identified by
    an email address in the format ``serviceAccount:SA_EMAIL_ADDRESS``. It extends
    the :class:`UserPrincipal` class but modifies the `kind`, `name`, and `description`
    to reflect that it represents a service account.
    """
    kind = 'serviceAccount'
    name = 'Service account'
    description = (
        'serviceAccount:SA_EMAIL_ADDRESS'
    )

    def __hash__(self) -> int:
        return hash(str(self))