from typing import ClassVar

import pydantic

from aegisx.types import DigestAlgorithm
from ._base import BaseAlgorithm


class SigningAlgorithm(BaseAlgorithm):
    use: ClassVar[str] = 'sig'

    dig: DigestAlgorithm | None = pydantic.Field(
        default=None
    )