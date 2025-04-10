from typing import ClassVar
from typing import Generic
from typing import NoReturn
from typing import TypeVar

import pydantic
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.oauth.types import Error
from ._authorizationserverresponse import AuthorizationServerResponse
from ._fields import IssuerIdentifierField
from ._fields import StateField


E = TypeVar('E', default=str)


class ErrorResponse(AuthorizationServerResponse, Generic[E]):
    model_config = {'extra': 'ignore'}
    code: ClassVar[None] = None

    error: E = pydantic.Field(
        default=...,
        title="Error",
        description=(
            "The error code returned from the server."
        )
    )

    error_description: str | None = pydantic.Field(
        default=None,
        title="Description",
        description=(
            "Human-readable ASCII text providing additional information, used "
            "to assist the client developer in understanding the error that "
            "occurred. Values for the `error_description` parameter MUST NOT "
            "include characters outside the set `%x20-21 / %x23-5B / %x5D-7E`."
        )
    )

    error_uri: HTTPResourceLocator | str | None = pydantic.Field(
        default=None,
        title="URI",
        description=(
            "A URI identifying a human-readable web page with information about the error, "
            "used to provide the client developer with additional information about the "
            "error. Values for the `error_uri` parameter MUST conform to the URI-reference "
            "syntax and thus MUST NOT include characters outside the set `%x21 / %x23-5B / "
            "%x5D-7E`."
        )
    )

    state: StateField
    iss: IssuerIdentifierField

    def fatal(self) -> NoReturn:
        Error(self.error_description).fatal()

    def is_error(self):
        return True

    def throw(self) -> NoReturn:
        raise Error(self.error_description)