import os
from typing import cast

import pydantic
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.oauth.types import ResponseType
from aegisx.ext.oauth.types import ValidationContext
from ._fields import StateField
from ._fields import AuthorizationRequestScopeField
from ._oidcclaimspec import OIDCClaimSpec


class AuthorizationRequestParameters(pydantic.BaseModel):
    response_type: ResponseType = pydantic.Field(
        default=...,
        title="Response type",
        description=(
            "The desired response type from the authorization "
            "endpoint."
        )
    )

    client_id: str = pydantic.Field(
        default=...,
        title="Client ID",
        description=(
            "The client identifier as described in Section 2.2 of "
            "RFC 6749."
        )
    )

    redirect_uri: HTTPResourceLocator | str | None = pydantic.Field(
        default=None,
        title="Redirect URI",
        description=(
            "The client redirection endpoint as described in Section 3.1.2 "
            "of RFC 6749."
        )
    )

    state: StateField
    scope: AuthorizationRequestScopeField

    # OpenID Connect
    response_mode: str | None = pydantic.Field(
        default=None,
        title="Response mode",
        description=(
            " Informs the authorization server of the mechanism to be used for returning "
            "parameters from the authorization endpoint. This use of this parameter is NOT "
            "RECOMMENDED when the response mode that would be requested is the default mode "
            "specified for `response_type`."
        )
    )

    nonce: str | None = pydantic.Field(
        default=None,
        title="Nonce",
        description=(
            " String value used to associate a Client session with an ID Token, "
            "and to mitigate replay attacks. The value is passed through unmodified "
            "from the Authentication Request to the ID Token. If present in the ID "
            "Token, Clients MUST verify that the nonce Claim Value is equal to the "
            "value of the nonce parameter sent in the Authentication Request. "
            "If present in the Authentication Request, Authorization Servers MUST "
            "include a nonce Claim in the ID Token with the Claim Value being the "
            "nonce value sent in the Authentication Request. The nonce value is a "
            "case sensitive string"
        )
    )

    max_age: int | None = pydantic.Field(
        default=None,
        title="Maximum authentication age",
        description=(
            "Specifies the allowable elapsed time in seconds since the last time the "
            "end-user was actively authenticated by the authorization server. If the "
            "When max_age is used, the ID Token returned includes an `auth_time` claim. "
            "Note that `max_age=0` is equivalent to `prompt=login`."
        )
    )

    claims: OIDCClaimSpec | None = pydantic.Field(
        default=None,
        title="Claims",
        description=(
            "This parameter is used to request that specific claims be returned. The "
            "value is a JSON object listing the requested claims. The `claims` parameter "
            "value is represented in an OAuth 2.0 request as UTF-8 encoded JSON (which "
            "ends up being form-urlencoded when passed as an OAuth parameter). When used "
            "in a Request Object value, the JSON is used as the value of the `claims` member."
        )
    )

    @pydantic.model_validator(mode='after')
    def postprocess(self, info: pydantic.ValidationInfo):
        if not info.context:
            return self
        ctx = cast(ValidationContext, info.context)
        if self.is_openid() and ctx['op'] == 'create':
            self.nonce = bytes.hex(os.urandom(32))
        return self

    def is_openid(self):
        return self.scope and 'openid' in self.scope