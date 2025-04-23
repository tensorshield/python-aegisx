import pydantic
from libcanonical.utils import deephash

from aegisx.ext.oauth.types import HTTPSResourceLocator
from aegisx.ext.oauth.types import IssuerIdentifier
from ._servermetadata import ServerMetadata


class ClientConfiguration(pydantic.BaseModel):
    """Configuration parameters for OAuth 2.x/OpenID Connect clients."""
    model_config = {'extra': 'forbid'}

    issuer: IssuerIdentifier = pydantic.Field(
        default=...
    )

    client_id: str = pydantic.Field(
        default=...
    )

    client_secret: str | None = pydantic.Field(
        default=None
    )

    authorization_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None
    )

    token_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None
    )

    metadata_url: HTTPSResourceLocator | None = pydantic.Field(
        default=None
    )

    default_redirect_uri: str | None = pydantic.Field(
        default=None
    )

    discoverable: bool = pydantic.Field(
        default=False
    )

    @property
    def metadata(self):
        metadata = ServerMetadata.model_validate({
            'issuer': self.issuer,
            'authorization_endpoint': self.authorization_endpoint,
            'token_endpoint': self.token_endpoint,
            'metadata_url': self.metadata_url,
        })
        if self.discoverable:
            metadata.discovered = False
        return metadata

    @property
    def __key__(self):
        return self.key(self.issuer, self.client_id)

    @staticmethod
    def key(issuer: IssuerIdentifier, client_id: str):
        return deephash((issuer, client_id), using='sha256', encode='hex')