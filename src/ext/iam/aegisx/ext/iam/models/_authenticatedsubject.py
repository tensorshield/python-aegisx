import pydantic
from libcanonical.types import EmailAddress

from aegisx.ext.iam.types import AUTHENTICATED
from aegisx.ext.iam.types import AuthenticatedPrincipal
from aegisx.ext.iam.types import DomainPrincipal
from aegisx.ext.iam.types import GroupPrincipal
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal
from ._subject import Subject



class AuthenticatedSubject(Subject):
    """
    Represents an authenticated subject in the IAM system.

    The :class:`AuthenticatedSubject` class extends the :class:`Subject`
    class and represents a subject (e.g., a user or service account)
    that is authenticated. This class overrides the `is_authenticated`
    method to always return `True`, indicating  that the subject is
    authenticated.
    """
    email: EmailAddress = pydantic.Field(
        default=...
    )

    email_verified: bool = pydantic.Field(
        default=False
    )

    service_account: bool = pydantic.Field(
        default=...
    )

    scope: set[str] = pydantic.Field(
        default_factory=set
    )

    groups: set[EmailAddress] = pydantic.Field(
        default_factory=set
    )

    @property
    def principal(self) -> UserPrincipal | ServiceAccountPrincipal:
        match self.service_account:
            case True:
                return ServiceAccountPrincipal.fromemail(self.email)
            case False:
                return UserPrincipal.fromemail(self.email)

    def principals(self) -> set[AuthenticatedPrincipal | DomainPrincipal | GroupPrincipal | ServiceAccountPrincipal | UserPrincipal]:
        return {
            self.principal,
            self.principal.domain,
            AUTHENTICATED,
            *map(GroupPrincipal.fromemail, self.groups),
            *map(DomainPrincipal, [x.domain for x in self.groups])
        }

    def is_authenticated(self) -> bool: # pragma: no cover
        """Return ``True`` if the subject is authenticated.

        This method always returns ``True`` for the :class:`AuthenticatedSubject`,
        indicating that the subject is considered authenticated.

        Returns:
            bool: Always returns ``True`` for an authenticated subject.
        """
        return True