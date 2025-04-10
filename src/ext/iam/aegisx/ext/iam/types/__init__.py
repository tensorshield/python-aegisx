from typing import Any
from typing import TypeVar
from typing import Union
from typing import TYPE_CHECKING

from ._anonymousprincipal import AnonymousPrincipal
from ._authenticatedprincipal import AuthenticatedPrincipal
from ._commonexpression import CommonExpression
from ._domainprincipal import DomainPrincipal
from ._groupprincipal import GroupPrincipal
from ._permission import Permission
from ._principal import Principal
from ._rolevalidationcontext import RoleValidationContext
from ._serviceaccountprincipal import ServiceAccountPrincipal
from ._userprincipal import UserPrincipal
from ._wildcardpermission import WildcardPermission
if TYPE_CHECKING:
    from aegisx.ext.iam.models import AuthorizationContext


__all__: list[str] = [
    'AnonymousPrincipal',
    'AuthenticatedPrincipal',
    'AuthorizationContextTypeVar',
    'CommonExpression',
    'DomainPrincipal',
    'GroupPrincipal',
    'Permission',
    'Principal',
    'PrincipalType',
    'RoleValidationContext',
    'ServiceAccountPrincipal',
    'UserPrincipal',
    'WildcardPermission',
]


AuthorizationContextTypeVar = TypeVar(
    'AuthorizationContextTypeVar',
    bound='AuthorizationContext'
)


PrincipalType = Union[
    AnonymousPrincipal,
    AuthenticatedPrincipal,
    DomainPrincipal,
    GroupPrincipal,
    ServiceAccountPrincipal,
    UserPrincipal
]

PrincipalTypeVar = TypeVar(
    'PrincipalTypeVar',
    bound=Principal[Any],
    default=Union[
        AnonymousPrincipal,
        AuthenticatedPrincipal,
        DomainPrincipal,
        GroupPrincipal,
        ServiceAccountPrincipal,
        UserPrincipal,
    ]
)

ANONYMOUS = AnonymousPrincipal.validate('allUsers')

AUTHENTICATED = AuthenticatedPrincipal.validate('allAuthenticatedUsers')