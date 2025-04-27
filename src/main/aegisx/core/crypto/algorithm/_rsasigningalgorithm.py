import pydantic

from ._signingalgorithm import SigningAlgorithm


class RSASigningAlgorithm(SigningAlgorithm):
    __supported_key_types__ = {'RSA'}

    pad: str = pydantic.Field(
        default=...
    )