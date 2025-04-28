import secrets
from typing import Literal

import pydantic
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher

from aegisx.types import EncryptionResult
from aegisx.types import SymmetricEncryptionKey
from aegisx.types import Undecryptable
from ._encryptionalgorithm import EncryptionAlgorithm


class AESGCMWrapEncryptionAlgorithm(EncryptionAlgorithm):
    model_config = {'populate_by_name': True}
    __supports_aad__ = True
    __supported_key_types__ = {'oct'}

    cip: Literal['AES+GCM'] = pydantic.Field(
        default=...
    )

    key_length: int = pydantic.Field(
        default=32,
        alias='len'
    )

    iv: int = pydantic.Field(
        default=...
    )

    def generate(self):
        return SymmetricEncryptionKey.generate(self.key_length)

    def decrypt(
        self,
        key: SymmetricEncryptionKey,
        result: EncryptionResult
    ) -> bytes:
        assert result.iv
        assert result.tag
        if not 8 <= len(result.iv) <= 128:
            raise ValueError(
                f"The initialization vector must be between 8 and 128 bytes: {len(result.iv)}."
            )
        c = Cipher(
            algorithm=algorithms.AES(key.k),
            mode=modes.GCM(result.iv, result.tag)
        )
        dec = c.decryptor()
        if result.aad:
            dec.authenticate_additional_data(result.aad)
        try:
            return dec.update(result.ct) + dec.finalize()
        except InvalidTag:
            raise Undecryptable(
                "The encrypted data could not be authenticated. Possible reasons include: "
                "you are using the wrong key or initialization vector, the ciphertext "
                "was tampered with, or wrong Additional Authenticated Data (AAD)."
            )

    def encrypt(
        self,
        key: SymmetricEncryptionKey,
        plaintext: bytes,
        aad: bytes | None = None
    ):
        iv = secrets.token_bytes(12)
        c = Cipher(
            algorithm=algorithms.AES(key.k),
            mode=modes.GCM(iv)
        )
        enc = c.encryptor()
        if aad is not None:
            enc.authenticate_additional_data(aad)
        result = EncryptionResult(
            ct=enc.update(plaintext) + enc.finalize(),
            iv=iv,
            aad=aad,
            tag=enc.tag
        )
        return result