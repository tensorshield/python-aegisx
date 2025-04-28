from typing import Literal

import pydantic
from cryptography.exceptions import InvalidSignature

from aegisx.types import Sr25519PrivateKey
from aegisx.types import Sr25519PublicKey
from ._ellipticcurvealgorithm import EllipticCurveAlgorithm
from ._signingalgorithm import SigningAlgorithm


class SrDSASigningAlgorithm(SigningAlgorithm, EllipticCurveAlgorithm):
    __supported_curves__ = {'Sr25519'}

    alg: Literal['EdDSA'] = pydantic.Field(
        default=...
    )

    kty: Literal['OKP'] = pydantic.Field( # type: ignore
        default='OKP'
    )

    def generate(self) -> Sr25519PrivateKey:
        return Sr25519PrivateKey.generate()

    def sign(
        self,
        key: Sr25519PrivateKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert not self.dig
        assert isinstance(key, Sr25519PrivateKey)
        return key.sign(message)

    def verify(
        self,
        key: Sr25519PublicKey,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        assert not self.dig
        assert isinstance(key, Sr25519PublicKey)
        try:
            key.verify(
                signature=signature,
                data=message,
            )
            return True
        except InvalidSignature:
            return False