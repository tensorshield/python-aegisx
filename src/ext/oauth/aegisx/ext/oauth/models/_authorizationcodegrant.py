from typing import Literal

import pydantic

from ._tokenrequestbase import TokenRequestBase


class AuthorizationCodeGrant(TokenRequestBase[Literal['authorization_code']]):
    code: str = pydantic.Field(
        default=...,
        title="Code",
        description="The authorization code received from the authorization server."
    )

    redirect_uri: str | None = pydantic.Field(
        default=None,
        title="Redirect URI",
        description=(
            "Required if the `redirect_uri` parameter was included in the "
            "authorization request as described in Section 4.1.1 of RFC 6749, "
            "and their values MUST be identical."
        )
    )