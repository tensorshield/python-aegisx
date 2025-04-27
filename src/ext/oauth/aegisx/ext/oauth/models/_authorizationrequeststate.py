import pydantic

from ._authorizationrequestparameters import AuthorizationRequestParameters


class AuthorizationRequestState(pydantic.BaseModel, extra='ignore'):
    #: Identifies the local client that was used to issue the
    #: authorization request.
    client_name: str = pydantic.Field(
        default=...
    )

    #: The local subject identifier (ours).
    sub: str | None = pydantic.Field(
        default=None
    )

    #: The parameters that were included in the authorization
    #: request.
    params: AuthorizationRequestParameters = pydantic.Field(
        default=...
    )

    @property
    def redirect_uri(self):
        return self.params.redirect_uri

    @property
    def state(self):
        assert self.params.state
        return self.params.state

    @pydantic.model_validator(mode='after')
    def postprocess(self):
        if not self.params.state:
            raise TypeError(
                'Can not instantiate an AuthorizationRequestState for'
                'requests that did not specify the "state" parameter.'
            )
        return self