from typing import Literal

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey

from ._ellipticcurvealgorithm import EllipticCurveAlgorithm
from ._signingalgorithm import SigningAlgorithm


class EdDSASigningAlgorithm(SigningAlgorithm, EllipticCurveAlgorithm):
    __supported_curves__ = {'Ed448', 'Ed25519'}

    alg: Literal['EdDSA'] = pydantic.Field(
        default=...
    )

    kty: Literal['OKP'] = pydantic.Field( # type: ignore
        default='OKP'
    )

    def generate(self):
        match str(self.crv):
            case 'Ed25519':
                return Ed25519PrivateKey.generate()
            case 'Ed448':
                return Ed448PrivateKey.generate()
            case _:
                raise NotImplementedError

    def sign(
        self,
        key: Ed448PrivateKey | Ed25519PrivateKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert not self.dig
        assert isinstance(key, (Ed448PrivateKey, Ed25519PrivateKey))
        return key.sign(message)

    def verify(
        self,
        key: Ed448PublicKey | Ed25519PublicKey,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        assert not self.dig
        assert isinstance(key, (Ed448PublicKey, Ed25519PublicKey))
        try:
            key.verify(signature=signature, data=message)
            return True
        except InvalidSignature:
            return False