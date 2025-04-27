from typing import Any
from typing import ClassVar

import pydantic

from aegisx.types import EllipticCurve


class EllipticCurveAlgorithm:
    __supported_curves__: ClassVar[set[str]]

    crv: EllipticCurve

    @pydantic.model_validator(mode='before')
    def preprocess(
        cls,
        values: dict[str, Any]
    ):
        crv = values.get('crv')
        if not crv:
            raise ValueError(f'The "crv" parameter is required.')
        if str(crv) not in cls.__supported_curves__:
            raise ValueError(
                f'Unknown curve: {crv}. Valid curves are '
                f'{", ".join(sorted(cls.__supported_curves__))}'
            )
        return values