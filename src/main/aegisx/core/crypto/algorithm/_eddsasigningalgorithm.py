from typing import Literal

import pydantic

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