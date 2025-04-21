import pydantic
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded

from ._authorizationserverresponse import AuthorizationServerResponse


class JARMAuthorizationServerResponse(AuthorizationServerResponse):
    response: JWECompactEncoded | JWSCompactEncoded = pydantic.Field(
        default=...,
        title="Response",
        description=(
            "The JWT Secured Authorization Response (JAR). The JWT is either "
            "signed, or signed and encrypted. If the JWT is both signed and "
            "encrypted, the JSON document will be signed then encrypted, with "
            "the result being a Nested JWT, as defined in RFC 7519"
        )
    )

    def is_encrypted(self) -> bool:
        return isinstance(self.response, JWECompactEncoded)

    def is_signed(self) -> bool:
        return True