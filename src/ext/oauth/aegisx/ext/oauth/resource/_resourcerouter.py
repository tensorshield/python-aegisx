import functools
from typing import Any
from typing import Callable

import fastapi

from ._requesthandler import RequestHandler


class ResourceRouter(fastapi.APIRouter):
    request_handler_class: type[RequestHandler] = RequestHandler

    def scope(self, scope: str):
        def decorator(func: Callable[..., Any] | RequestHandler) -> RequestHandler:
            if not isinstance(func, self.request_handler_class):
                func = functools.wraps(func)(self.request_handler_class(func))
            return func.with_scope(scope) # type: ignore
        return decorator