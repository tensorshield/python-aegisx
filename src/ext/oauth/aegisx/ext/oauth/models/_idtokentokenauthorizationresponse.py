from ._fields import IDTokenField
from ._tokenauthorizationresponse import TokenAuthorizationResponse


class IDTokenTokenAuthorizationResponse(TokenAuthorizationResponse):
    id_token: IDTokenField