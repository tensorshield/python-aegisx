import pydantic

from aegisx.ext.oauth.types import GrantTypeLiteral
from ._tokenresponse import TokenResponse


class Grant(pydantic.BaseModel):
    name: str
    grant_type: GrantTypeLiteral
    issuer: str
    obtained: int
    scope: set[str]
    response: TokenResponse

    @property
    def access_token(self):
        return self.response.access_token

    @property
    def expires_in(self):
        return self.response.expires_in

    @property
    def refresh_token(self):
        return self.response.refresh_token

    @property
    def token_type(self):
        return self.response.token_type