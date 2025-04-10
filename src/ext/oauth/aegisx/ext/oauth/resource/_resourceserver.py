from typing import Awaitable
from typing import Callable

import fastapi
from starlette.middleware.base import BaseHTTPMiddleware

from ._authenticationbackend import AuthenticationBackend
from ._authenticationbackend import NullAuthenticationBackend


class ResourceServer(fastapi.FastAPI):

    def __init__(
        self,
        backends: list[AuthenticationBackend] | None = None
    ):
        super().__init__()
        self.backends = backends or []
        self.add_middleware(BaseHTTPMiddleware, dispatch=self.authenticate)

    async def authenticate(
        self,
        request: fastapi.Request,
        call_next: Callable[[fastapi.Request], Awaitable[fastapi.Response]]
    ):
        backend = self.select(request)
        await backend.authenticate(request)
        return await call_next(request)

    def select(self, request: fastapi.Request):
        for backend in self.backends:
            if not backend.can_authenticate(request):
                continue
            break
        else:
            backend = NullAuthenticationBackend()
        return backend
