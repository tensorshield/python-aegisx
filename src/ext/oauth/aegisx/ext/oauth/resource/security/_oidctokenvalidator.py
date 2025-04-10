from aegisx.ext.oauth.models import OIDCToken
from aegisx.ext.oauth.models import ServerMetadata
from aegisx.ext.jose import JSONWebSignature
from aegisx.ext.jose import Signature
from aegisx.ext.jose import TokenValidator
from libcanonical.types import HTTPResourceLocator


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

    async def verify(
        self,
        jws: JSONWebSignature,
        payload: OIDCToken
    ) -> Signature | None:
        jwks = self.jwks
        if isinstance(payload.iss, HTTPResourceLocator)\
        and self.is_trusted_issuer(payload.iss):
            metadata = await ServerMetadata.get(payload.iss)
            jwks = metadata.jwks
        return await jwks.verify(jws)
