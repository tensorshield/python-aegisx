import secrets
from typing import Literal

import pydantic
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.padding import PKCS7

from aegisx.types import DigestAlgorithm
from aegisx.types import EncryptionResult
from aegisx.types import SymmetricEncryptionKey
from aegisx.types import Undecryptable
from ._encryptionalgorithm import EncryptionAlgorithm


class AESCBCEncryptionAlgorithm(EncryptionAlgorithm):
    model_config = {'populate_by_name': True}
    __supports_aad__ = True
    __supported_key_types__ = {'oct'}

    cip: Literal['AES+CBC'] = pydantic.Field(
        default=...
    )

    dig: DigestAlgorithm = pydantic.Field(
        default=...
    )

    key_length: int = pydantic.Field(
        default=32,
        alias='len'
    )

    iv: int = pydantic.Field(
        default=...
    )

    @staticmethod
    def encode_int(n: int, l: int):
        return n.to_bytes(l // 8, 'big')

    @staticmethod
    def bitsize(v: bytes):
        return len(v) * 8

    def generate(self):
        return SymmetricEncryptionKey.generate(self.key_length)

    def decrypt(
        self,
        key: SymmetricEncryptionKey,
        result: EncryptionResult
    ) -> bytes:
        assert result.iv
        if len(result.tag) != (self.key_length // 2):
            raise Undecryptable(f"Invalid tag length: {len(result.tag)}")
        if len(key.k) != (self.key_length):
            raise Undecryptable(
                f"Algorithm {type(self).__name__} requires a key length "
                f"of {self.key_length}, actual: {len(key.k)}."
            )
        if len(result.iv) != 16:
            raise Undecryptable(f"Initialization Vector (IV) must be 16 bytes, got {len(result.iv)}")
        hk = key.k[:self.key_length // 2]
        ek = key.k[self.key_length // 2:]
        assert len(hk) == len(ek)

        cipher = Cipher(
            algorithm=algorithms.AES(ek),
            mode=modes.CBC(result.iv)
        )
        dec = cipher.decryptor()
        p = dec.update(result.ct) + dec.finalize()
        u = PKCS7(algorithms.AES.block_size).unpadder() # type: ignore
        pt = u.update(p) + u.finalize()

        hmac = self.hmac(hk, result.aad, result.iv, result.ct)
        if not secrets.compare_digest(bytes(result.tag), hmac):
            raise Undecryptable("MAC verification failure.")
        return pt

    def encrypt(
        self,
        key: SymmetricEncryptionKey,
        plaintext: bytes,
        aad: bytes | None = None
    ):
        aad = aad or b''
        if len(key.k) != self.key_length:
            raise ValueError(
                f"Algorithm {type(self).__name__} requires a key of length {self.key_length}, got {len(key.k)}."
            )
        l = self.key_length // 2
        hk = key.k[:l]
        ek = key.k[l:]
        assert len(hk) == len(ek)

        iv = secrets.token_bytes(self.iv)
        cipher = Cipher(
            algorithms.AES(ek),
            modes.CBC(iv),
        )
        enc = cipher.encryptor()
        pad = PKCS7(algorithms.AES.block_size).padder() # type: ignore
        d = pad.update(plaintext) + pad.finalize()
        ct = enc.update(d) + enc.finalize()
        tag = self.hmac(hk, aad, iv, ct)
        return EncryptionResult(ct=ct, iv=iv, tag=tag, aad=aad)


    def hmac(self, k: bytes, aad: bytes, iv: bytes, e: bytes):
        al = self.encode_int(self.bitsize(aad), 64)
        h = hmac.HMAC(k, self.dig.hash('cryptography'))
        h.update(aad)
        h.update(iv)
        h.update(e)
        h.update(al)
        m = h.finalize()
        return m[:self.key_length // 2]