from typing import Generic
from typing import TypeVar

import pydantic

from aegisx.ext.oauth.types import GrantTypeLiteral


G = TypeVar('G')


class TokenRequestBase(pydantic.BaseModel, Generic[G]):
    grant_type: GrantTypeLiteral = pydantic.Field(
        default=...,
        title="Grant type",
        description=(
            "Specifies the grant type requested by the client."
        )
    )

    client_id: str | None = pydantic.Field(
        default=None,
        title="Client ID",
        description=(
            "Request if the client is not authenticating with the "
            " authorization server as described in Section 3.2.1 of "
            "RFC 6749, or if the client uses the `client_secret_post` "
            "method to authenticate."
        )
    )

    client_secret: str | None = pydantic.Field(
        default=None,
        title="Client secret",
        description=(
            "Request if the client uses the `client_secret_post` "
            "method to authenticate itself."
        )
    )

    @pydantic.model_validator(mode='after')
    def postprocess(self):
        if self.client_secret and not self.client_id:
            raise ValueError(
                "Both the \"client_id\" and \"client_secret\" "
                "parameters must be provided."
            )
        return self