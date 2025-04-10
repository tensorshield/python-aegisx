import asyncio
import asyncio.coroutines
import inspect

import fastapi


class AuthenticationBackend:
    """The base class for resource server authentication backends."""
    _is_coroutine = asyncio.coroutines._is_coroutine # type: ignore
    priority: int = 1000

    @property
    def __call__(self):
        return self.authenticate

    @property
    def __signature__(self):
        return inspect.signature(self.authenticate)

    def __init__(self):
        # Check if the asyncio.iscoroutinefunction() call returns
        # True for this object, since it depends on a private
        # symbol.
        assert asyncio.iscoroutinefunction(self)

    def can_authenticate(self, request: fastapi.Request) -> bool:
        """Return ``True`` if the backend can authenticate the request."""
        raise NotImplementedError

    def is_authenticated(self, request: fastapi.Request) -> bool:
        return getattr(request.state, 'authenticated', False)

    def handle(self, request: fastapi.Request):
        if self.is_authenticated(request):
            return
        return self.authenticate(request)

    async def authenticate(self, request: fastapi.Request) -> None:
        """Authenticate the request and set the ``principal`` attribute
        on the state. Other claims may be set.
        """
        raise NotImplementedError


class NullAuthenticationBackend(AuthenticationBackend):

    async def authenticate(self, request: fastapi.Request) -> None:
        return