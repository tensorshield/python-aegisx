from aegisx.types import EllipticCurve
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from ._ellipticcurvealgorithm import EllipticCurveAlgorithm
from ._signingalgorithm import SigningAlgorithm


assert EllipticCurve.__cryptography_curves__


class ECDSASigningAlgorithm(SigningAlgorithm, EllipticCurveAlgorithm):
    __supported_curves__ = set(EllipticCurve.__cryptography_curves__.keys())
    __supported_key_types__ = {'EC'}

    def generate(self):
        assert self.crv.curve_class
        return generate_private_key(self.crv.curve_class())

    def sign(
        self,
        key: EllipticCurvePrivateKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert self.dig
        assert isinstance(key, EllipticCurvePrivateKey)
        h = self.dig.hash('cryptography')
        return key.sign(
            message,
            self._get_signature_algorithm(h, message, prehashed)
        )

    def verify(
        self,
        key: EllipticCurvePublicKey,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ):
        assert self.dig
        assert isinstance(key, EllipticCurvePublicKey)
        h = self.dig.hash('cryptography')
        try:
            key.verify(
                signature,
                message,
                self._get_signature_algorithm(h, message, prehashed)
            )
            return True
        except InvalidSignature:
            return False

    def _get_signature_algorithm(
        self,
        h: HashAlgorithm,
        message: bytes,
        prehashed: bool
    ):
        if prehashed and len(message) != h.digest_size:
            raise ValueError(
                f'Invalid message length {len(message)}. '
                f'Hash {h.name} requires length {h.digest_size}.'
            )
        match prehashed:
            case True:
                algorithm = ECDSA(Prehashed(h))
            case False:
                algorithm = ECDSA(h)
        return algorithm