from typing import Literal

import pydantic
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from aegisx.types import EncryptionResult
from aegisx.types import SymmetricEncryptionKey
from ._encryptionalgorithm import EncryptionAlgorithm


class AESKeyWrapEncryptionAlgorithm(EncryptionAlgorithm):
    model_config = {'populate_by_name': True}
    __supported_key_types__ = {'oct'}

    cip: Literal['AESWRAP'] = pydantic.Field(
        default=...
    )

    key_length: int = pydantic.Field(
        default=32,
        alias='len'
    )

    def generate(self):
        return SymmetricEncryptionKey.generate(self.key_length)

    def decrypt(
        self,
        key: SymmetricEncryptionKey,
        result: EncryptionResult
    ) -> bytes:
        return aes_key_unwrap(key.k, result.ct)

    def encrypt(
        self,
        key: SymmetricEncryptionKey,
        plaintext: bytes
    ):
        if len(plaintext) < 16:
            raise ValueError('The key to wrap must be at least 16 bytes')
        return EncryptionResult(
            ct=aes_key_wrap(key.k, plaintext)
        )