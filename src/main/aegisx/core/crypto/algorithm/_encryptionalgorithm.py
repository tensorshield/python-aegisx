from typing import Literal

import pydantic

from ._base import BaseAlgorithm


class EncryptionAlgorithm(BaseAlgorithm):
    alg: str | None = pydantic.Field(
        default=None
    )

    use: Literal['enc'] = pydantic.Field(
        default=...
    )