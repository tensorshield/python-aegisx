import asyncio
import logging
import time
from typing import AsyncGenerator
from typing import Iterable
from typing import Literal
from typing import TYPE_CHECKING

import httpx

from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import Grant
from aegisx.ext.oauth.models import TokenResponse
from aegisx.ext.oauth.protocols import IClientRepository
from aegisx.ext.oauth.types import AccessTokenType
if TYPE_CHECKING:
    from aegisx.ext.oauth.client import Client


class BaseResourceServerAuth(httpx.Auth):
    """Base class for all OAuth 2.x/OpenID Connect authentication flows
    with resource servers.
    """
    config: ClientConfiguration
    ephemeral_port: int
    grant: Grant | None
    leeway: int = 0
    logger: logging.Logger = logging.getLogger(__name__)
    refresh_status_codes: set[int]
    response_mode: str
    response_type: str
    scope: set[str]


    def __init__(
        self,
        name: str,
        config: ClientConfiguration,
        *,
        repo: IClientRepository,
        scope: Iterable[str] | None = None,
        refresh_status_codes: set[int] = {401, 403},
        response_type: Literal['code', 'id_token', 'code id_token', 'code id_token token'] = 'code',
        response_mode: Literal['query', 'query.jwt'] = 'query',
        ephemeral_port: int = 0,
        logger: logging.Logger | None = None
    ):
        self.config = config
        self.ephemeral_port = ephemeral_port
        self.grant = None
        self.lock = asyncio.Lock()
        self.logger = logger or self.logger
        self.name = name
        self.refresh_status_codes = refresh_status_codes
        self.response_mode = response_mode
        self.response_type = response_type
        self.repo = repo
        self.scope = set(scope or [])

    def authenticate_request(self, request: httpx.Request) -> None:
        """Authenticate a request using the access token."""
        assert self.grant
        match self.grant.token_type:
            case AccessTokenType.BEARER:
                assert self.grant.access_token
                request.headers['Authorization'] = f'Bearer {self.grant.access_token}'
            case _:
                raise NotImplementedError(
                    f"Tokens of type {self.grant.token_type} are not implemented."
                )

    def client_factory(self) -> 'Client':
        from aegisx.ext.oauth.client import Client # TODO
        return Client.fromconfig(self.config)

    def get_ephemeral_port(self) -> int:
        if not self.ephemeral_port:
            raise NotImplementedError
        return self.ephemeral_port

    def is_invalid(self, response: httpx.Response):
        """Return a boolean indicating if the access token is
        expired, invalid or otherwise not usable.
        """
        # Technically not conforming to spec, but not every resource
        # server conforms to the spec.
        return response.status_code in self.refresh_status_codes

    def must_refresh(self, request: httpx.Request, now: int | None = None) -> bool:
        """Return a boolean indicating if the access token must be
        refreshed.
        """
        if not self.grant or not self.grant.expires_in:
            # If there is no grant or the server did not send the "expires_in"
            # parameter, we do not know if we must refresh.
            return False
        now = int(now or time.time())
        return (now - self.grant.obtained - self.leeway) > self.grant.expires_in

    async def async_auth_flow(
        self,
        request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        if self.grant is None:
            self.grant = await self.repo.grant(self.name)
        async with self.lock:
            if not self.grant\
            or not self.grant.access_token\
            or self.must_refresh(request):
                await self.obtain(request)
        self.authenticate_request(request)

        assert self.grant is not None
        assert self.grant.access_token is not None
        response = yield request
        if self.is_invalid(response):
            await response.aread()
            async with self.lock:
                await self.obtain(request)
            self.authenticate_request(request)
            yield request

    async def authorize(self) -> None:
        raise NotImplementedError(
            f'{type(self).__name__} does not support the authorization code flow.'
        )

    async def obtain(self, request: httpx.Request) -> None:
        """Obtain a new access token."""
        if not self.grant or not self.grant.refresh_token:
            await self.authorize()
            return
        await self.refresh(request)

    async def refresh(self, request: httpx.Request) -> None:
        """Refresh the current access token."""
        # Fetch the grant from the repository as another
        # caller might have expired this access token,
        # since BaseResourceServerAuth instances can be
        # long-lived (application scoped).
        grant = await self.repo.grant(self.name)
        if not grant:
            raise TypeError(f'Grant {self.name} does not exist.')
        if grant and not grant.refresh_token:
            raise TypeError(
                f'Grant "{grant.grant_type}" did not provide a '
                'refresh token.'
            )
        async with self.client_factory() as client:
            self.logger.info(
                'Refreshing access token for grant %s',
                self.name
            )
            response = await client.refresh(grant.refresh_token)
            if response.is_error():
                raise NotImplementedError(response.root)
            else:
                self.grant = await self.process_response(response)

    async def process_response(self, response: TokenResponse) -> Grant:
        if response.is_error():
            raise TypeError('Error responses can not be processed.')
        grant = Grant(
            name=self.name,
            grant_type='refresh_token',
            issuer=self.config.metadata.issuer,
            obtained=int(time.time()),
            response=response,
            scope=self.scope
        )
        await self.repo.persist(grant, name=self.name, config=self.config)
        self.logger.info(
            'Obtained fresh access token for grant %s',
            self.name
        )
        return grant

    def __repr__(self):
        return f"{type(self).__name__}(name='{self.name}')"