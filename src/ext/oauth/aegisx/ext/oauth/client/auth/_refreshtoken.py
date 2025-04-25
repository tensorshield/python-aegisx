from ._baseresourceserver import BaseResourceServerAuth


class RefreshTokenAuth(BaseResourceServerAuth):
    """A :class:`~BaseResourceServerAuth` implementation for use with a
    refresh token. It assumes that the grant specified by the `name`
    parameter is already present in the repository.
    """
    __module__: str = 'aegisx.ext.oauth.client.auth'