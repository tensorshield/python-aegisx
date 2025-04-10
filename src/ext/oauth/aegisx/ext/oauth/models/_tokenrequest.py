import pydantic

from ._authorizationcodegrant import AuthorizationCodeGrant


class TokenRequest(
    pydantic.RootModel[
        AuthorizationCodeGrant
    ]
):
    pass