from aegisx.types import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from ._ellipticcurvealgorithm import EllipticCurveAlgorithm
from ._signingalgorithm import SigningAlgorithm


assert EllipticCurve.__cryptography_curves__

class ECDSASigningAlgorithm(SigningAlgorithm, EllipticCurveAlgorithm):
    __supported_curves__ = set(EllipticCurve.__cryptography_curves__.keys())
    __supported_key_types__ = {'EC'}

    def sign(
        self,
        key: EllipticCurvePrivateKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert self.dig
        assert isinstance(key, EllipticCurvePrivateKey)
        algorithm: ECDSA
        h = self.dig.hash('cryptography')
        match prehashed:
            case True:
                algorithm = ECDSA(Prehashed(h))
            case False:
                if len(message) != h.digest_size:
                    raise ValueError(
                        f'Invalid message length {len(message)}. '
                        f'Hash {h.name} requires length {h.digest_size}.'
                    )
                algorithm = ECDSA(h)
        return key.sign(
            data=message,
            signature_algorithm=algorithm
        )