import pydantic

from ._signingalgorithm import SigningAlgorithm


class RSASigningAlgorithm(SigningAlgorithm):
    __supported_key_types__ = {'RSA'}

    alg: str | None = pydantic.Field(
        default=None
    )


    pad: str = pydantic.Field(
        default=...
    )