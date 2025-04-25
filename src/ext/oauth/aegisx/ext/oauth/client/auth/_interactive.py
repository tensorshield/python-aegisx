import contextlib
import http
import http.server
import os
import urllib.parse
import webbrowser
from threading import Event
from threading import Thread
from typing import Any
from typing import TypeVar
from typing import TYPE_CHECKING

from aegisx.ext.oauth.types import AccessTokenType
from ._baseresourceserver import BaseResourceServerAuth
if TYPE_CHECKING:
    from aegisx.ext.oauth.client import Client


C = TypeVar('C', bound='Client')

SUCCESS_RESPONSE = b'You can now close this window.'


class InteractiveAuth(BaseResourceServerAuth):
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
            self.grant = await self.process_response(token)