from typing import Any
from typing import NoReturn
from typing import TypeVar

import httpx
import pydantic

from aegisx.ext.oauth.types import Error
from ._authorizationserverresponse import AuthorizationServerResponse


E = TypeVar('E', default=str)


class NonProtocolErrorResponse(AuthorizationServerResponse):
    model_config = {'extra': 'allow'}

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(cls, values: Any, info: pydantic.ValidationInfo):
        # Note that this must be after ErrorResponse in a
        # response union.
        if info.context and isinstance(info.context, httpx.Response):
            if info.context.status_code < 400:
                raise ValueError(f"not an error response: {info.context.status_code}")
        return values

    def fatal(self) -> NoReturn:
        Error(repr(self)).fatal()

    def is_error(self):
        return True

    def throw(self) -> NoReturn:
        raise Error(repr(self))