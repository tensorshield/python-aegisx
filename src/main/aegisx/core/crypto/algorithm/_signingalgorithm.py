from typing import Literal

import pydantic

from aegisx.types import DigestAlgorithm
from ._base import BaseAlgorithm


class SigningAlgorithm(BaseAlgorithm):
    use: Literal['sig'] = pydantic.Field(
        default=...
    )

    dig: DigestAlgorithm | None = pydantic.Field(
        default=None
    )