from typing import Literal

import pydantic

from ._tokenrequestbase import TokenRequestBase


class RefreshTokenRequest(TokenRequestBase[Literal['refresh_token']]):
    refresh_token: str = pydantic.Field(
        default=...,
        title="Refresh token",
        description="The refresh token issued to the client."
    )