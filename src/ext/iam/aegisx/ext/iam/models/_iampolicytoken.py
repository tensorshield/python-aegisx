import pydantic
from libcanonical.types import DigestSHA256

from aegisx.ext.jose import JSONWebToken


class IAMPolicyToken(JSONWebToken):
    required = {'iss', 'sub', 'dig'}

    dig: DigestSHA256 = pydantic.Field(
        default=...,
        title="Policy digest",
        description=(
            "The computed digest of the `IAMPolicy` instance."
        )
    )