import urllib.parse
from typing import Union

import pydantic

from ._authorizationcodegrant import AuthorizationCodeGrant
from ._refreshtokenrequest import RefreshTokenRequest


class TokenRequest(
    pydantic.RootModel[
        Union[
            AuthorizationCodeGrant,
            RefreshTokenRequest
        ]
    ]
):
    
    @pydantic.model_serializer(mode='wrap')
    def serialize(
        self,
        nxt: pydantic.SerializerFunctionWrapHandler,
        info: pydantic.SerializationInfo
    ):
        if info.mode != 'form': # type: ignore
            return nxt(self)
        return urllib.parse.urlencode(
            self.model_dump(
                mode='json',
                exclude_defaults=True,
                exclude_unset=True,
                exclude_none=True
            )
        )