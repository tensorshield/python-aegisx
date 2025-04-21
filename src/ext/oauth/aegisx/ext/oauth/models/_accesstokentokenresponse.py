from typing import TYPE_CHECKING

import pydantic
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded

from ._authorizationserverresponse import AuthorizationServerResponse
from ._fields import AccessTokenExpiresInField
from ._fields import AccessTokenField
from ._fields import AccessTokenScopeField
from ._fields import AccessTokenTypeField
from ._fields import StateField
from ._oidctoken import OIDCToken
from ._tokenresponsemixin import TokenResponseMixin
if TYPE_CHECKING:
    from aegisx.ext.oauth.client import OIDCTokenValidator


class AccessTokenTokenResponse(AuthorizationServerResponse, TokenResponseMixin):
    model_config = {'extra': 'ignore'}

    access_token: AccessTokenField
    token_type: AccessTokenTypeField
    expires_in: AccessTokenExpiresInField
    scope: AccessTokenScopeField
    state: StateField

    refresh_token: str | None = pydantic.Field(
        default=None,
        title="Refresh token",
        description=(
            "The refresh token, which can be used to obtain new access tokens "
            "using the same authorization grant as described in Section 6 of "
            "RFC 6749."
        )
    )

    id_token: JWECompactEncoded | JWSCompactEncoded | None = pydantic.Field(
        default=None,
        title="ID Token",
        description=(
            "JSON Web Token (JWT) that contains claims about the authentication "
            "event. It MAY contain other claims."
        )
    )

    jwt: OIDCToken | None = pydantic.Field(
        default=None,
        exclude=True
    )

    async def validate_id_token(
        self,
        validator: 'OIDCTokenValidator'
    ):
        self.jwt = await validator.validate(self.id_token)