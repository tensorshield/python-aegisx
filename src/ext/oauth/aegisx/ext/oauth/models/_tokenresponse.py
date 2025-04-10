import pydantic

from aegisx.ext.oauth.types import AccessTokenType
from ._accesstokentokenresponse import AccessTokenTokenResponse
from ._errorresponse import ErrorResponse
from ._nonprotocolerrorresponse import NonProtocolErrorResponse
from ._proofofpossessiontokenresponse import ProofOfPossessionTokenResponse


class TokenResponse(
    pydantic.RootModel[
        ProofOfPossessionTokenResponse |
        AccessTokenTokenResponse |
        ErrorResponse |
        NonProtocolErrorResponse
    ]
):

    @property
    def access_token(self) -> str | None:
        return getattr(self.root, 'access_token', None)

    @property
    def expires_in(self) -> int | None:
        return getattr(self.root, 'expires_in', None)

    @property
    def refresh_token(self) -> str | None:
        return getattr(self.root, 'refresh_token')

    @property
    def token_type(self) -> AccessTokenType:
        return getattr(self.root, 'token_type')

    def fatal(self):
        assert isinstance(self.root, (ErrorResponse, NonProtocolErrorResponse))
        self.root.fatal()

    def is_encrypted(self):
        return self.root.is_encrypted()

    def is_error(self):
        return isinstance(self.root, (ErrorResponse, NonProtocolErrorResponse))

    def is_signed(self):
        return self.root.is_signed()