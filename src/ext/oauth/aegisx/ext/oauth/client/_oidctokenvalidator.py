import time
from typing import Any
from typing import TYPE_CHECKING

from aegisx.ext.jose import JSONWebKeySet
from aegisx.ext.jose import TokenValidator

from aegisx.ext.oauth.const import OICD_STANDARD_CLAIMS
from aegisx.ext.oauth.models import OIDCToken
from aegisx.ext.oauth.models import ServerMetadata
from aegisx.ext.oauth.models import AuthorizationRequestParameters
from aegisx.ext.oauth.models import TokenResponse
if TYPE_CHECKING:
    from ._client import Client


class OIDCTokenValidator(TokenValidator[OIDCToken]):

    def __init__(
        self,
        client: 'Client',
        metadata: ServerMetadata,
        params: AuthorizationRequestParameters,
        grant: TokenResponse,
        jwks: JSONWebKeySet | None = None
    ):
        assert metadata.is_discovered()
        jwks = jwks or metadata.jwks
        self.client = client
        self.grant = grant
        self.metadata = metadata
        self.params = params

        required = set(OICD_STANDARD_CLAIMS)
        if params.max_age:
            required.add('auth_time')
        if params.nonce:
            required.add('nonce')
        if params.claims and params.claims.id_token:
            required.update(params.claims.id_token.requested())
        super().__init__(
            OIDCToken,
            issuer=metadata.issuer,
            audience={client.client_id},
            jwks=jwks,
            required=required
        )

    def get_context(self) -> dict[str, Any]:
        ctx = super().get_context()
        ctx.update({
            'client_id': self.client.client_id,
            'grant': self.grant,
            'metadata': self.metadata,
            'now': int(time.time()),
            'params': self.params
        })
        return ctx