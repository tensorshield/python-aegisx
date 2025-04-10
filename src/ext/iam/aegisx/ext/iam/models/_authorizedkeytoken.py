import pydantic
from libcanonical.types import DigestSHA256

from aegisx.ext.jose import JSONWebToken


class AuthorizedKeyToken(JSONWebToken):
    required = {'iss', 'thumbprint'}

    thumbprint: DigestSHA256 = pydantic.Field(
        default=...,
        title="Thumbprint",
        description=(
            "The computed digest of the authorized "
            "keys' thumbprint."
        )
    )