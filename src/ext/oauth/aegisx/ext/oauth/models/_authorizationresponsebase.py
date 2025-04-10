from ._authorizationserverresponse import AuthorizationServerResponse
from ._fields import IssuerIdentifierField
from ._fields import StateField


class AuthorizationResponseBase(AuthorizationServerResponse):
    model_config = {'extra': 'forbid'}
    state: StateField
    iss: IssuerIdentifierField