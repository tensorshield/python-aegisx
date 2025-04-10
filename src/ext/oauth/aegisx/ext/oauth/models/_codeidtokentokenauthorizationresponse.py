from ._fields import IDTokenField
from ._codetokenauthorizationresponse import CodeTokenAuthorizationResponse

class CodeIDTokenTokenAuthorizationResponse(CodeTokenAuthorizationResponse):
    id_token: IDTokenField