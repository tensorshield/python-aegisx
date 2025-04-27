from aegisx.types import EllipticCurve

from ._ellipticcurvealgorithm import EllipticCurveAlgorithm
from ._signingalgorithm import SigningAlgorithm


assert EllipticCurve.__cryptography_curves__

class ECDSASigningAlgorithm(SigningAlgorithm, EllipticCurveAlgorithm):
    __supported_curves__ = set(EllipticCurve.__cryptography_curves__.keys())
    __supported_key_types__ = {'EC'}