import collections
import functools
import inspect
from inspect import Parameter
from typing import cast
from typing import Any
from typing import Callable
from typing import Iterable

import fastapi

from .types import ResourceServerException
from .types import InvalidRequestScope


class RequestHandler:
    requires: set[str]

    @functools.cached_property
    def __signature__(self):
        sig = inspect.signature(self.func)
        params = collections.OrderedDict(sig.parameters)
        params['_scope'] = Parameter(
            kind=Parameter.KEYWORD_ONLY,
            name='_scope',
            annotation=set[str],
            default=fastapi.Depends(self.get_scope)
        )
        return sig.replace(
            parameters=[
                Parameter(
                    kind=Parameter.POSITIONAL_ONLY,
                    name='_httprequest',
                    annotation=fastapi.Request,
                ),
                *list(params.values())
            ]
        )

    def __init__(
        self,
        func: Callable[..., Any]
    ):
        self.func = func
        self.requires = set()
        inspect.markcoroutinefunction(self)
        assert inspect.iscoroutinefunction(self)

    def get_scope(self, request: fastapi.Request) -> set[str]:
        return getattr(request.state, 'scope', set())

    def with_scope(self, scope: str):
        self.requires.add(scope)
        return self

    def validate_scope(self, request: fastapi.Request, granted: set[str]):
        missing = self.requires - granted
        if missing:
            raise InvalidRequestScope(missing)

    async def __call__(self, *args: Any, **kwargs: Any):
        request = cast(fastapi.Request, kwargs.pop('_httprequest'))
        assert getattr(request.state, 'subject', None)
        try:
            self.validate_scope(
                request=request,
                granted=set(cast(Iterable[str], kwargs.pop('_scope') or []))
            )
            return await self.func(*args, **kwargs)
        except ResourceServerException as e:
            return e.http()