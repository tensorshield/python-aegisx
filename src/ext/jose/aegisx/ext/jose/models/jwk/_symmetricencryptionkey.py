import os
import secrets
from typing import ClassVar
from typing import Literal

import pydantic
import cryptography.exceptions
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hmac
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import IntegrityViolation
from ._jsonwebkeybase import JSONWebKeyBase


T_LEN = 16


class SymmetricEncryptionKey(
    JSONWebKeyBase[
        Literal['oct'],
        Literal['encrypt', 'decrypt', 'unwrapKey', 'wrapKey'],
        Literal['enc']
    ]
):
    crv: ClassVar[None] = None
    thumbprint_claims = ['k', 'kty']

    k: Base64 = pydantic.Field(
        default=...,
        title="Key",
        description=(
            "The `k` (key value) parameter contains the value of the symmetric (or "
            "other single-valued) key. It is represented as the base64url encoding "
            "of the octet sequence containing the key value."
        )
    )

    @classmethod
    def generate(cls, alg: JSONWebAlgorithm, length: int | None = None):
        length = length or alg.config.length
        assert length
        return cls.model_validate({
            **alg.config.params(),
            'k': Base64(os.urandom(length // 8))
        })

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return alg.cipher in {'AES+GCM', 'AES+CBC', 'AESWRAP'}

    def decrypt(self, result: EncryptionResult) -> AwaitableBytes:
        alg = result.alg
        match alg.config.cipher:
            case 'AESWRAP':
                return self.unwrap(result)
            case 'AES+GCM':
                return self.decrypt_aes_gcm(result)
            case 'AES+CBC':
                return self.decrypt_aes_cbc(result)
            case _:
                raise NotImplementedError(f"Unsupported cipher: {alg.config.cipher}")

    def decrypt_aes_cbc(self, result: EncryptionResult): # pragma: no cover
        length = result.alg.config.length
        dig = result.alg.config.dig
        if length is None:
            raise TypeError(
                f"The length could not be determined from algorithm {result.alg} "
                "and the `length` parameter was None."
            )
        if len(result.tag) != (result.alg.length // 8):
            raise ValueError(f"Invalid tag length: {len(result.tag)}")
        if len(self.k) != (length * 2 // 8):
            raise ValueError(
                f"Algorithm {result.alg} requires a key length "
                f"of {length * 2 // 8}, actual: {len(self.k)}."
            )
        if len(result.iv) != 16:
            raise ValueError(f"Initialization Vector (IV) must be 16 bytes, got {len(result.iv)}")
        if dig is None:
            raise ValueError(f"Algorithm {result.alg} did not specify a hash algorithm.")
        hk = self.k[:length // 8]
        ek = self.k[length // 8:]
        assert len(hk) == len(ek)

        cipher = Cipher(
            algorithm=algorithms.AES(ek),
            mode=modes.CBC(result.iv)
        )
        dec = cipher.decryptor()
        p = dec.update(result.ct) + dec.finalize()
        u = PKCS7(algorithms.AES.block_size).unpadder() # type: ignore
        pt = u.update(p) + u.finalize()

        hmac = self.hmac(result.alg, hk, result.aad, result.iv, result.ct)
        if not secrets.compare_digest(bytes(result.tag), hmac):
            raise ValueError("MAC verification failure.")

        return AwaitableBytes(pt)

    def decrypt_aes_gcm(self, result: EncryptionResult):
        if not 8 <= len(result.iv) <= 128:
            raise ValueError(
                f"The initialization vector must be between 8 and 128 bytes: {len(result.iv)}."
            )
        c = Cipher(
            algorithm=algorithms.AES(self.k),
            mode=modes.GCM(result.iv, result.tag)
        )
        dec = c.decryptor()
        dec.authenticate_additional_data(result.aad)
        try:
            return AwaitableBytes(dec.update(result.ct) + dec.finalize())
        except cryptography.exceptions.InvalidTag:
            raise IntegrityViolation(
                "The encrypted data could not be authenticated. Possible reasons include: "
                "you are using the wrong key or initialization vector, the ciphertext "
                "was tampered with, or wrong Additional Authenticated Data (AAD)."
            )

    def encrypt(
        self,
        pt: bytes,
        aad: bytes | None = None,
        alg: JSONWebAlgorithm | None = None
    ) -> EncryptionResult:
        alg = alg or self.alg
        if alg is None:
            raise TypeError("The `alg` parameter can not be None.")
        match alg.cipher:
            case 'AES+GCM':
                return self.encrypt_gcm(pt, aad or b'', alg)
            case 'AES+CBC':
                return self.encrypt_cbc(pt, aad or b'', alg)
            case 'AESWRAP':
                return self.wrap(alg, pt)
            case _:
                raise NotImplementedError(
                    f"Algorithm {alg} specifies unsupported cipher: {alg.config.cipher}"
                )

    def encrypt_cbc(
        self,
        pt: bytes,
        aad: bytes,
        alg: JSONWebAlgorithm
    ) -> EncryptionResult: # pragma: no cover
        if len(self.k) != ((alg.length // 8) * 2):
            raise ValueError(
                f"Algorithm {alg} requires a key of length {(alg.length // 8) * 2}, got {len(self.k)}."
            )
        hk = self.k[:alg.length // 8]
        ek = self.k[alg.length // 8:]
        assert len(hk) == len(ek)

        iv = os.urandom(128 // 8) # type: ignore
        cipher = Cipher(
            algorithms.AES(ek),
            modes.CBC(iv),
        )
        enc = cipher.encryptor()
        pad = PKCS7(algorithms.AES.block_size).padder() # type: ignore
        d = pad.update(pt) + pad.finalize()
        ct = enc.update(d) + enc.finalize()
        tag = self.hmac(alg, hk, aad, iv, ct)
        return EncryptionResult(alg=alg, ct=ct, iv=iv, tag=tag, aad=aad)

    def encrypt_gcm(
        self,
        pt: bytes,
        aad: bytes,
        alg: JSONWebAlgorithm
    ) -> EncryptionResult:
        iv = os.urandom(12)
        c = Cipher(
            algorithm=algorithms.AES(self.k),
            mode=modes.GCM(iv)
        )
        enc = c.encryptor()
        enc.authenticate_additional_data(aad)
        result = EncryptionResult(
            alg=alg,
            ct=enc.update(pt) + enc.finalize(),
            iv=iv,
            aad=aad,
            tag=enc.tag
        )
        return result

    def hmac(self, alg: JSONWebAlgorithm, k: bytes, aad: bytes, iv: bytes, e: bytes):
        assert alg.config.length
        al = self.encode_int(self.bitsize(aad), 64)
        h = hmac.HMAC(k, self.get_hash(alg))
        h.update(aad)
        h.update(iv)
        h.update(e)
        h.update(al)
        m = h.finalize()
        return m[:alg.length // 8]

    def is_asymmetric(self) -> bool:
        return False

    def unwrap(self, result: EncryptionResult):
        return AwaitableBytes(aes_key_unwrap(self.k, result.ct))

    def wrap(self, alg: JSONWebAlgorithm, pt: bytes):
        return EncryptionResult(
            alg=alg,
            ct=aes_key_wrap(self.k, pt)
        )

    @staticmethod
    def encode_int(n: int, l: int):
        return n.to_bytes(l // 8, 'big')

    @staticmethod
    def bitsize(v: bytes):
        return len(v) * 8

    def __bytes__(self) -> bytes:
        return bytes(self.k)