from typing import Any
from typing import TypeVar
from typing import TYPE_CHECKING

from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JWSHeader

if TYPE_CHECKING:
    from ._accesstokenbearer import AccessTokenBearer


T = TypeVar('T', bound=Any, default=Any)


class AccessTokenValidator(TokenValidator[T]):

    def __init__(
        self,
        security: 'AccessTokenBearer[T]', 
        types: Any,
    ):
        self.security = security
        super().__init__(types=types)

    def is_accepted_issuer(self, payload: JSONWebToken) -> bool:
        result = self.security.is_accepted_issuer(payload) # type: ignore
        if result == NotImplemented:
            result = super().is_accepted_issuer(payload)
        assert isinstance(result, bool)
        return result

    async def get_verification_jwks(
        self,
        header: JWSHeader,
        payload: T
    ):
        return await self.security.get_verification_jwks(
            header=header,
            payload=payload,
            default=self.jwks
        )