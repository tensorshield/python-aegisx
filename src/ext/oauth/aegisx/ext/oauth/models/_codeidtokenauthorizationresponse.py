from ._codeauthorizationresponse import CodeAuthorizationResponse
from ._fields import IDTokenField


class CodeIDTokenAuthorizationResponse(CodeAuthorizationResponse):
    id_token: IDTokenField