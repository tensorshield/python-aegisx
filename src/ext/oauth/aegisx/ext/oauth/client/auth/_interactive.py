import contextlib
import http
import http.server
import os
import time
import urllib.parse
import webbrowser
from threading import Event
from threading import Thread
from typing import Any
from typing import AsyncGenerator
from typing import Awaitable
from typing import Callable
from typing import Literal
from typing import TypeVar
from typing import TYPE_CHECKING

import httpx
from httpx import Request
from httpx import Response

from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import TokenResponse
from aegisx.ext.oauth.types import AccessTokenType
if TYPE_CHECKING:
    from aegisx.ext.oauth.client import Client


C = TypeVar('C', bound='Client')

SUCCESS_RESPONSE = b'You can now close this window.'


class InteractiveAuth(httpx.Auth):
    """Interactive authentication where the resource owner is redirected
    to the authorization endpoint.
    """
    access_token: str | None = None
    expires_in : int | None = None
    obtained: int | None
    leeway: int = 15
    refresh_token: str | None = None
    refresh_status_codes: set[int] = {401, 403}
    response_type: str
    result: urllib.parse.ParseResult | None = None
    token_type: AccessTokenType | None = None

    class request_handler(http.server.SimpleHTTPRequestHandler):
        auth: 'InteractiveAuth'
        event: Event
        ephemeral_port: int

        def do_GET(self) -> None:
            content = "You can now close this window."
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            try:
                p = urllib.parse.urlparse(f'http://127.0.0.1:{self.ephemeral_port}{self.path}')
                response = self.auth.on_redirected(p)
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except Exception:
                response = b'Internal server error'
                self.send_header('Content-Length', str(len(response)))
                self.wfile.write(str.encode(content))

        def log_message(self, format: str, *args: Any) -> None:
            pass

    def __init__(
        self,
        config: ClientConfiguration,
        *,
        response_type: Literal['code', 'id_token', 'code id_token', 'code id_token token'] = 'code',
        response_mode: Literal['query', 'query.jwt'] = 'query',
        ephemeral_port: int = 0,
        grant: TokenResponse | None = None,
        access_token: str | None = None,
        obtained: int | None = None,
        expires_in: int | None = None,
        refresh_token: str | None = None,
        token_type: AccessTokenType | None = None,
        scope: set[str] | None = None,
        persist: Callable[['TokenResponse'], Awaitable[None]] | None = None
    ):
        self.access_token = access_token
        self.config = config
        self.ephemeral_port = ephemeral_port
        self.expires_in = expires_in
        self.obtained = obtained
        self.response_mode = response_mode
        self.response_type = response_type
        self.scope = scope
        self.event = Event()
        self._persist = persist
        if grant is not None:
            self.access_token = grant.access_token
            self.expires_in = grant.expires_in
            self.refresh_token = grant.refresh_token
            self.token_type = grant.token_type

    def authenticate_request(self, request: Request) -> None:
        """Authenticate a request using the access token."""
        assert self.access_token
        match self.token_type:
            case AccessTokenType.BEARER:
                request.headers['Authorization'] = f'Bearer {self.access_token}'
            case _:
                raise NotImplementedError(
                    f"Tokens of type {self.token_type} are not implemented."
                )

    def client_factory(self):
        from aegisx.ext.oauth.client import Client # TODO
        return Client.fromconfig(self.config)

    def get_ephemeral_port(self) -> int:
        if not self.ephemeral_port:
            raise NotImplementedError
        return self.ephemeral_port

    def is_invalid(self, response: Response):
        """Return a boolean indicating if the access token is
        expired, invalid or otherwise not usable.
        """
        # Technically not conforming to spec, but not every resource
        # server conforms to the spec.
        return response.status_code in self.refresh_status_codes

    def must_refresh(self, request: Request, now: int | None = None):
        """Return a boolean indicating if the access token must be
        refreshed.
        """
        if not self.obtained or not self.expires_in:
            return False
        now = int(now or time.time())
        return (now - self.obtained - self.leeway) > self.expires_in

    def on_redirected(self, result: urllib.parse.ParseResult | None) -> bytes:
        self.result = result
        self.event.set()
        return SUCCESS_RESPONSE

    def wait(self):
        self.event.wait()
        assert self.result
        return self.result

    @contextlib.contextmanager
    def redirect_endpoint(self, port: int):
        self.event = Event()
        server = self.server_factory(port)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield
        server.shutdown()
        self.result = None

    def server_factory(self, port: int):
        return http.server.ThreadingHTTPServer(
            server_address=('127.0.0.1', port),
            RequestHandlerClass=type(
                'RequestHandler',
                (self.request_handler,),
                {
                    'auth': self,
                    'event': self.event,
                    'ephemeral_port': port
                }
            )
        )

    async def authorize(self) -> None:
        port = self.get_ephemeral_port()
        redirect_uri = f'http://127.0.0.1:{port}'
        state = bytes.hex(os.urandom(16))
        async with self.client_factory() as client:
            request, url = client.authorize_url(
                self.response_type,
                redirect_uri=redirect_uri,
                state=state,
                scope=self.scope,
                response_mode=self.response_mode
            )
            with self.redirect_endpoint(port):
                webbrowser.open(url)
                result = self.wait()
            response = await client.on_redirected(result)
            if response.is_error():
                response.fatal()
            token = await client.obtain(request, response)
            if token.is_error():
                token.fatal()
            self.access_token = token.access_token
            self.expires_in = token.expires_in
            self.obtained = int(time.time())
            self.refresh_token = token.refresh_token
            self.token_type = token.token_type
            await self.persist(token)

    async def async_auth_flow(
        self,
        request: httpx.Request
    ) -> AsyncGenerator[Request, Response]:
        if not self.access_token or self.must_refresh(request):
            await self.obtain(request)
        self.authenticate_request(request)
        assert self.access_token is not None
        response = yield request
        if self.is_invalid(response):
            await self.obtain(request)
            self.authenticate_request(request)
            yield request

    async def obtain(self, request: Request) -> None:
        """Obtain a new access token."""
        if not self.refresh_token:
            await self.authorize()
            return
        await self.refresh(request)

    async def refresh(self, request: Request) -> None:
        """Refresh the current access token."""
        async with self.client_factory() as client:
            grant = await client.refresh(self.refresh_token)
            await self.persist(grant)
            self.access_token = grant.access_token
            self.expires_in = grant.expires_in
            self.refresh_token = grant.refresh_token
            self.token_type = grant.token_type

    async def persist(self, grant: 'TokenResponse') -> None:
        if self._persist is None:
            return
        await self._persist(grant)