import urllib.parse
from typing import Any

import pydantic

from ._codeauthorizationresponse import CodeAuthorizationResponse
from ._codeidtokentokenauthorizationresponse import CodeIDTokenTokenAuthorizationResponse
from ._codeidtokenauthorizationresponse import CodeIDTokenAuthorizationResponse
from ._codetokenauthorizationresponse import CodeTokenAuthorizationResponse
from ._idtokenauthorizationresponse import IDTokenAuthorizationResponse
from ._idtokentokenauthorizationresponse import IDTokenTokenAuthorizationResponse
from ._jarmauthorizationresponse import JARMAuthorizationServerResponse
from ._tokenauthorizationresponse import TokenAuthorizationResponse
from ._errorresponse import ErrorResponse


class AuthorizationResponse(
    pydantic.RootModel[
        JARMAuthorizationServerResponse |
        CodeIDTokenTokenAuthorizationResponse |
        IDTokenTokenAuthorizationResponse |
        IDTokenAuthorizationResponse |
        CodeTokenAuthorizationResponse |
        CodeIDTokenAuthorizationResponse |
        CodeAuthorizationResponse |
        TokenAuthorizationResponse |
        ErrorResponse
    ]
):

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess_response(
        cls,
        response: Any | urllib.parse.ParseResult
    ) -> Any:
        if isinstance(response, urllib.parse.ParseResult):
            if response.query and response.fragment:
                raise ValueError(
                    "The response from the authorization endpoint must either "
                    "have a query or a fragment component, but not both."
                )
            if not response.query and not response.fragment:
                raise ValueError(
                    "The authorization server did not send a response in the "
                    "query or the fragment component."
                )
            match bool(response.query):
                case True:
                    try:
                        response = dict(urllib.parse.parse_qsl(response.query))
                    except ValueError:
                        raise ValueError(
                            "the query component of the authorization response "
                            "is malformed."
                        )
                case False:
                    raise NotImplementedError("Fragment responses are not implemented.")
        return response

    @property
    def code(self) -> str | None:
        return getattr(self.root, 'code', None)

    @property
    def iss(self) -> str | None:
        return getattr(self.root, 'iss', None)

    @property
    def redirect_uri(self) -> str | None:
        return getattr(self.root, 'redirect_uri', None)

    @property
    def state(self) -> str | None:
        return getattr(self.root, 'state', None)

    def fatal(self):
        if not isinstance(self.root, ErrorResponse):
            raise UserWarning(
                "Can not call AuthorizationResponse.fatal() on non-error "
                "responses."
            )
        self.root.fatal()

    def is_error(self):
        return self.root.is_error()