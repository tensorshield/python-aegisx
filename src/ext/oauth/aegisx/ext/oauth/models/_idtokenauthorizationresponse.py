from ._authorizationresponsebase import AuthorizationResponseBase
from ._fields import IDTokenField


class IDTokenAuthorizationResponse(AuthorizationResponseBase):
    id_stoken: IDTokenField

    def is_encrypted(self) -> bool:
        return False

    def is_signed(self) -> bool:
        return False