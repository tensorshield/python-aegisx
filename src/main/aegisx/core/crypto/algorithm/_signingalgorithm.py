from typing import Any
from typing import ClassVar

import pydantic

from aegisx.types import DigestAlgorithm
from ._base import BaseAlgorithm


class SigningAlgorithm(BaseAlgorithm):
    use: ClassVar[str] = 'sig'

    dig: DigestAlgorithm | None = pydantic.Field(
        default=None
    )

    def sign(
        self,
        key: Any,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        raise NotImplementedError