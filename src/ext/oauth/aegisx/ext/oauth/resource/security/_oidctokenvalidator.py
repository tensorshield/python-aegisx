from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JWSHeader
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.oauth.models import OIDCToken
from aegisx.ext.oauth.models import ServerMetadata


class OIDCTokenValidator(TokenValidator[OIDCToken]):

    def __init__(
        self,
        audience: set[str] | None = None,
        issuer: set[str] | None = None
    ):
        super().__init__(
            types=OIDCToken,
            audience=audience,
            issuer=issuer
        )

    async def get_verification_jwks(
        self,
        header: JWSHeader,
        payload: OIDCToken
    ):
        jwks = self.jwks
        if isinstance(payload.iss, HTTPResourceLocator)\
        and self.is_trusted_issuer(payload.iss):
            metadata = await ServerMetadata.get(payload.iss)
            jwks = metadata.jwks
        return jwks