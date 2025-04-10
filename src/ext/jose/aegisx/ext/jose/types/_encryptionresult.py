from typing import Union
from typing import TYPE_CHECKING

import pydantic

from ._jsonwebalgorithm import JSONWebAlgorithm
if TYPE_CHECKING:
    from aegisx.ext.jose.models import JSONWebKey


class EncryptionResult(pydantic.BaseModel):
    alg: JSONWebAlgorithm = pydantic.Field(
        default=...
    )

    ct: bytes = pydantic.Field(
        default=...
    )

    iv: bytes = pydantic.Field(
        default_factory=bytes
    )

    tag: bytes = pydantic.Field(
        default_factory=bytes
    )

    aad: bytes = pydantic.Field(
        default_factory=bytes
    )

    epk: Union['JSONWebKey', None] = pydantic.Field(
        default=None
    )

    apv: bytes = pydantic.Field(
        default_factory=bytes
    )

    apu: bytes = pydantic.Field(
        default_factory=bytes
    )

    async def _await(self):
        return self

    def __await__(self):
        return self._await().__await__()

    def __bytes__(self):
        return self.ct