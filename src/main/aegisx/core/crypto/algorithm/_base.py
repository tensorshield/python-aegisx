from typing import Any
from typing import ClassVar

import pydantic

from aegisx.types import EncryptionResult
from aegisx.types import SymmetricEncryptionKey


class BaseAlgorithm(pydantic.BaseModel, extra='forbid'):
    __supports_aad__: ClassVar[bool] = False
    __supported_curves__: ClassVar[set[str]] = set()
    __supported_key_types__: ClassVar[set[str]] = set()

    #: Identifiers for the algorithm in the :mod:`aegisx` library.
    name: str | None = pydantic.Field(
        default=None
    )

    kty: str | None = pydantic.Field(
        default=None
    )

    @pydantic.field_validator('kty', mode='after')
    def postprocess_kty(cls, value: str | None):
        if value is not None and str(value) not in cls.__supported_key_types__:
            raise ValueError(f'Unsupported key type: {value}')
        return value

    def decrypt(
        self,
        key: Any,
        result: EncryptionResult
    ) -> bytes:
        raise NotImplementedError

    def derive(self, *args: Any, **kwargs: Any) -> SymmetricEncryptionKey:
        raise NotImplementedError

    def encrypt(
        self,
        key: Any,
        plaintext: bytes
    ) -> EncryptionResult:
        raise NotImplementedError

    def epk(self, key: Any) -> Any:
        raise NotImplementedError

    def generate(self) -> Any:
        raise NotImplementedError

    def sign(
        self,
        key: Any,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        raise NotImplementedError

    def verify(
        self,
        key: Any,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        raise NotImplementedError