from ._authorizationresponsebase import AuthorizationResponseBase
from ._fields import AccessTokenExpiresInField
from ._fields import AccessTokenField
from ._fields import AccessTokenScopeField
from ._fields import AccessTokenTypeField
from ._fields import StateField
from ._tokenresponsemixin import TokenResponseMixin


class TokenAuthorizationResponse(AuthorizationResponseBase, TokenResponseMixin):
    access_token: AccessTokenField
    token_type: AccessTokenTypeField
    expires_in: AccessTokenExpiresInField
    scope: AccessTokenScopeField
    state: StateField