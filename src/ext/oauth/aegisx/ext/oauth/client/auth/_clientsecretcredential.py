from typing import TYPE_CHECKING

import httpx
from aegisx.ext.jose import JSONWebKey

from aegisx.ext.oauth.types import ClientAuthenticationMethod
if TYPE_CHECKING:
    from aegisx.ext.oauth.models import TokenRequest


class ClientSecretCredential(httpx.Auth):
    alg: str | None = None

    @property
    def jwk(self) -> JSONWebKey | None:
        if not self.client_secret:
            return None
        return JSONWebKey.model_validate({
            'kty': 'oct',
            'alg': self.alg or 'HS',
            'k': self.client_secret
        })

    def __init__(
        self,
        client_id: str,
        client_secret: str | None,
        *,
        method: ClientAuthenticationMethod | str = ClientAuthenticationMethod.none,
        alg: str | None = None
    ):
        if isinstance(method, str): # type: ignore
            method = ClientAuthenticationMethod(method)
        self.alg = alg
        self.client_id = client_id
        self.client_secret = client_secret
        self.method = method

    def add_to_grant(self, grant: 'TokenRequest'):
        if self.method == ClientAuthenticationMethod.client_secret_post:
            grant.root.client_id = self.client_id
            grant.root.client_secret = self.client_secret