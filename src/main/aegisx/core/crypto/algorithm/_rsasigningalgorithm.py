import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from aegisx.types import PaddingAlgorithm
from ._signingalgorithm import SigningAlgorithm


class RSASigningAlgorithm(SigningAlgorithm):
    __supported_key_types__ = {'RSA'}

    alg: str | None = pydantic.Field(
        default=None
    )


    pad: PaddingAlgorithm = pydantic.Field(
        default=...
    )

    def sign(
        self,
        key: RSAPrivateKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert self.dig
        assert isinstance(key, RSAPrivateKey)
        h = self.dig.hash('cryptography')
        p = self.pad.padding(h)
        if prehashed:
            h = Prehashed(h)
        return key.sign(
            message,
            padding=p,
            algorithm=h
        )

    def verify(
        self,
        key: RSAPublicKey,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        assert self.dig
        assert isinstance(key, RSAPublicKey)
        h = self.dig.hash('cryptography')
        p = self.pad.padding(h)
        if prehashed:
            h = Prehashed(h)
        try:
            key.verify(
                signature=signature,
                data=message,
                padding=p,
                algorithm=h
            )
            return True
        except InvalidSignature:
            return False