from typing import ClassVar
from typing import Literal

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.asymmetric.padding import MGF1
from cryptography.hazmat.primitives.asymmetric.padding import PSS
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from libcanonical.types import Base64
from libcanonical.types import AwaitableBool

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeybase import JSONWebKeyBase


class JSONKeyRSAPublic(JSONWebKeyBase[
    Literal['RSA'],
    Literal['sign', 'verify', 'unwrapKey', 'wrapKey']
]):
    model_config = {
        'title': 'RSA Public Key'
    }

    crv: ClassVar[None] = None
    thumbprint_claims = ["e", "kty", "n"]

    n: Base64 = pydantic.Field(
        default=...,
        title="Modulus",
        description=(
            "The `n` (modulus) parameter contains the modulus "
            "value for the RSA public key."
        )
    )

    e: Base64 = pydantic.Field(
        default=...,
        title="Exponent",
        description=(
            "The `e` (exponent) parameter contains the exponent "
            "value for the RSA public key."
        )
    )

    @property
    def public_numbers(self) -> RSAPublicNumbers:
        return RSAPublicNumbers(n=int(self.n), e=int(self.e))

    @property
    def public_key(self):
        return self.public_numbers.public_key()

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return alg.config.kty == 'RSA'

    def get_public_key(self):
        return JSONKeyRSAPublic.model_validate(self.model_dump())

    def get_signature_params(self, alg: JSONWebAlgorithm):
        p = h = None
        match alg:
            case 'PS256':
                p = PSS(mgf=MGF1(SHA256()), salt_length=32)
                h = SHA256()
            case 'PS384':
                p = PSS(mgf=MGF1(SHA384()), salt_length=48)
                h = SHA384()
            case 'PS512':
                p = PSS(mgf=MGF1(SHA512()), salt_length=64)
                h = SHA512()
            case 'RS256':
                p = PKCS1v15()
                h = SHA256()
            case 'RS384':
                p = PKCS1v15()
                h = SHA384()
            case 'RS512':
                p = PKCS1v15()
                h = SHA512()
            case _:
                raise ValueError(f'Unknown algorithm: {alg}')
        if p is None or h is None: # type: ignore
            raise ValueError(f"Unable to determine signing algorithm: {alg}")
        return p, h

    def get_encryption_params(self, alg: JSONWebAlgorithm):
        p = None
        match alg.config.pad:
            case 'PKCS1':
                p = PKCS1v15()
            case 'OAEP':
                p = OAEP(
                    mgf=MGF1(self.get_hash(alg)),
                    algorithm=self.get_hash(alg),
                    label=None
                )
            case _:
                raise ValueError(f"Algorithm {alg} specifies unsupported padding: {alg.config.pad}")
        return p,

    def is_asymmetric(self) -> bool:
        return True

    def encrypt(
        self,
        pt: bytes,
        aad: bytes | None,
        alg: JSONWebAlgorithm
    ) -> EncryptionResult:
        return EncryptionResult(
            alg=alg,
            ct=self.public_key.encrypt(pt, *self.get_encryption_params(alg))
        )

    def verify(
        self,
        signature: bytes,
        message: bytes
    ) -> AwaitableBool:
        assert self.alg is not None
        try:
            self.public_key.verify(
                signature, message, *self.get_signature_params(self.alg)
            )
            return AwaitableBool(True)
        except InvalidSignature:
            return AwaitableBool(False)