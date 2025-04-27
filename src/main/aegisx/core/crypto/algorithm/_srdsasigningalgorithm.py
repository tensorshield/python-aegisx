from typing import Literal

import pydantic

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