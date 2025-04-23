import functools
import os
import secrets
import urllib.parse
from typing import Any
from typing import Callable
from typing import TypeVar

import httpx

from aegisx.ext.oauth.models import AuthorizationResponse
from aegisx.ext.oauth.models import AuthorizationRequestParameters
from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import OIDCToken
from aegisx.ext.oauth.models import ServerMetadata
from aegisx.ext.oauth.models import TokenRequest
from aegisx.ext.oauth.models import TokenResponse
from aegisx.ext.oauth.types import IssuerIdentifier
from aegisx.ext.oauth.types import ClientAuthenticationMethod
from aegisx.ext.oauth.types import ClientConfigurationError
from aegisx.ext.oauth.types import HTTPSResourceLocator
from aegisx.ext.oauth.types import NeedsDiscovery
from aegisx.ext.oauth.types import ResponseType
from .auth import ClientSecretCredential
from ._oidctokenvalidator import OIDCTokenValidator

R = TypeVar('R')
U = TypeVar("U", bound="Client")


class Client(httpx.AsyncClient):

    @property
    def client_id(self):
        assert self.credential
        return self.credential.client_id

    @staticmethod
    def needs_credential(func: Callable[..., R]) -> Callable[..., R]:
        @functools.wraps(func)
        def f(self: 'Client', *args: Any, **kwargs: Any) -> R:
            if not self.credential:
                raise ValueError(f"{type(self).__name__}.credential can not be None.")
            return func(self, *args, **kwargs)
        return f

    @staticmethod
    def needs_discovery(func: Callable[..., R]) -> Callable[..., R]:
        @functools.wraps(func)
        def f(self: 'Client', *args: Any, **kwargs: Any) -> R:
            metadata = kwargs.setdefault('metadata', self.metadata)
            if not metadata.is_discovered():
                raise NeedsDiscovery
            return func(self, *args, **kwargs)
        return f

    @staticmethod
    def needs_param(name: str):
        def decorator_factory(func: Callable[..., R]):
            @functools.wraps(func)
            def f(self: 'Client', *args: Any, **kwargs: Any):
                metadata = kwargs.get('metadata') or self.metadata
                if not hasattr(metadata, name):
                    raise AttributeError(f"ServerMetadata has no attribute {name}")
                if getattr(metadata, name) is None:
                    raise ClientConfigurationError(
                        f"The \"{name}\" parameter was not discovered or explicitely "
                        "configured."
                    )
                return func(self, *args, **kwargs)
            return f
        return decorator_factory

    @classmethod
    def fromconfig(cls, config: ClientConfiguration):
        return cls(
            issuer=config.issuer,
            credential=ClientSecretCredential(
                client_id=config.client_id,
                client_secret=config.client_secret,
                method='client_secret_post'
            ),
            metadata=config.metadata
        )

    @classmethod
    def fromservermetadata(cls, credential: ClientSecretCredential, metadata: ServerMetadata):
        return cls(
            issuer=IssuerIdentifier(metadata.issuer),
            credential=credential,
            metadata=metadata
        )

    def __init__(
        self,
        *,
        issuer: IssuerIdentifier | str,
        credential: ClientSecretCredential | None = None,
        authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
        metadata: ServerMetadata | None = None,
        oidc_validator: Callable[['Client', 'ServerMetadata', AuthorizationRequestParameters, 'TokenResponse'], OIDCTokenValidator] = OIDCTokenValidator,
        discoverable: bool = False
    ):
        self.credential = credential
        self.discoverable = discoverable
        self.oidc_validator = oidc_validator

        # TODO: Add commonly used parameters for now. For any extended features
        # the caller must provide the `metadata` parameter.
        manual_discovery = (not metadata or not metadata.is_discovered()) and not discoverable
        self.metadata = metadata or ServerMetadata.model_validate({
            'issuer': issuer,
            'authorization_endpoint': authorization_endpoint,
            'token_endpoint': token_endpoint,
        })
        if manual_discovery:
            self.metadata.discovered = True
            assert self.metadata.is_discovered()
        super().__init__(
            timeout=60.0,
            verify=not os.getenv('AEGISX_SSL_VERIFY') == '0'
        )

    @needs_discovery
    @needs_param('authorization_endpoint')
    def authorize_url(
        self,
        response_type: ResponseType | str,
        redirect_uri: str | None = None,
        state: str | None = None,
        scope: set[str] | None = None,
        *,
        metadata: ServerMetadata | None = None,
        **kwargs: Any,
    ) -> HTTPSResourceLocator:
        assert self.credential
        metadata = metadata or self.metadata
        if scope is not None:
            kwargs['scope'] = scope
        params = AuthorizationRequestParameters.model_validate(
            {
                'client_id': self.credential.client_id,
                'response_type': response_type,
                'redirect_uri': redirect_uri,
                'state': state,
                **kwargs
            },
            context={'op': 'create'}
        )
        q = params.model_dump(
            mode='json',
            exclude_none=True,
            exclude_defaults=True,
            exclude_unset=True
        )
        assert metadata.authorization_endpoint
        return params, metadata.authorization_endpoint.with_query(**q) # type: ignore

    async def connect(self):
        if not self.metadata.is_discovered() and self.discoverable:
            await self.metadata.discover(client=self)
        return self

    @needs_discovery
    @needs_param('token_endpoint')
    async def obtain(
        self,
        request: AuthorizationRequestParameters,
        response: AuthorizationResponse,
        metadata: ServerMetadata
    ):
        """Obtain a new access token using an authorization code.
        
        Args:
            request (AuthorizationRequestParameters): the parameters of the
                authorization request that produced the response.
            response (AuthorizationResponse): the response from the authorization
                endpoint.
        """
        assert self.credential
        assert metadata.token_endpoint
        if not response.code:
            raise ValueError(
                f"{type(response.root).__name__} does not supply an "
                "authorization code."
            )

        # The "state" parameter in the Authorization Response MUST
        # match the "state" parameter that was included in the
        # Authorization Request.
        if request.state:
            if not response.state:
                raise ValueError(
                    "The authorization server did not return the "
                    "\"state\" parameter."
                )
            if not secrets.compare_digest(request.state, response.state):
                raise ValueError(
                    "The \"state\" parameter returned by the authorization "
                    "server did not match with the local value."
                )

        # Clients that support this specification MUST extract the value of
        # the iss parameter from authorization responses they receive if the
        # parameter is present. Clients MUST compare the extracted and URL-
        # decoded value to the issuer identifier of the authorization server
        # where the authorization request was sent to. This comparison MUST
        # use simple string comparison as defined in Section 6.2.1. of [RFC3986].
        # If the value does not match the expected issuer identifier, clients
        # MUST reject the authorization response and MUST NOT proceed with
        # the authorization grant.
        if response.iss:
            if not secrets.compare_digest(response.iss, metadata.issuer):
                raise ValueError(
                    "The \"iss\" parameter sent by the authorization "
                    "server does not match the known metadata: "
                    f"{metadata.issuer}"
                )

        # The request and response are valid, proceed to
        # obtain the token. If the server issued an ID
        # token, validate the token according to the
        # OpenID Connect Core specification.
        grant = TokenRequest.model_validate({
            'grant_type': 'authorization_code',
            'code': response.code,
            'redirect_uri': request.redirect_uri
        })
        self.credential.add_to_grant(grant)
        token = await self._grant(metadata.token_endpoint, grant)
        if token.id_token:
            validator = self.oidc_validator(self, metadata, request, token)
            await token.validate_id_token(validator)
        return token

    async def on_redirected(
        self,
        result: urllib.parse.ParseResult,
        state: str | None = None
    ):
        response = AuthorizationResponse.model_validate(obj=result)
        return response

    @needs_discovery
    @needs_param('token_endpoint')
    async def refresh(
        self,
        refresh_token: str,
        metadata: ServerMetadata
    ) -> TokenResponse:
        assert self.credential
        assert metadata.token_endpoint
        request = TokenRequest.model_validate({
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })
        self.credential.add_to_grant(request)
        return await self._grant(metadata.token_endpoint, request)

    @needs_discovery
    @needs_param('userinfo_endpoint')
    async def userinfo(
        self,
        token: str,
        metadata: ServerMetadata | None,
        endpoint: str | None = None
    ) -> OIDCToken:
        assert metadata is not None
        assert metadata.userinfo_endpoint is not None
        response = await self.get(
            url=endpoint or metadata.userinfo_endpoint,
            headers={'Authorization': f'Bearer {token}'}
        )
        return OIDCToken.model_validate(response.json())

    async def __aenter__(self: U) -> U:
        await super().__aenter__()
        await self.connect()
        return self

    async def _grant(self, endpoint: str, grant: TokenRequest):
        self._select_client_secret_jwt_alg(self.metadata)
        response = await self.post(
            url=endpoint,
            data=grant.model_dump(
                mode='json',
                exclude_unset=True,
                exclude_defaults=True,
                exclude_none=True
            )
        )
        try:
            return TokenResponse.model_validate(
                response.json(),
                context=response
            )
        except Exception:
            raise NotImplementedError(f"invalid response from authorization server:\n\n{response.text}.")

    def _select_client_secret_jwt_alg(self, metadata: ServerMetadata):
        assert self.credential
        if self.credential.method != ClientAuthenticationMethod.client_secret_jwt:
            return
        if self.credential.alg:
            return
        candidates = [
            x for x in
            metadata.token_endpoint_auth_signing_alg_values_supported or []
            if str.startswith(x, 'HS')
        ]
        if not candidates:
            raise ValueError(
                "Unable to select a suitable algorithm to use with "
                "client authentication method client_secret_jwt from "
                f"algorithms: {metadata.token_endpoint_auth_signing_alg_values_supported}"
            )
        self.credential.alg = candidates[0]