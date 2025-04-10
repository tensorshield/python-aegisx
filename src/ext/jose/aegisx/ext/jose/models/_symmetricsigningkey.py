import hmac
import os
import secrets
from typing import ClassVar
from typing import Literal

import pydantic
from libcanonical.types import AwaitableBool
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64

from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeybase import JSONWebKeyBase


class SymmetricSigningKey(
    JSONWebKeyBase[
        Literal['oct'],
        Literal['sign', 'verify'],
        Literal['sig']
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
    def generate(cls, alg: JSONWebAlgorithm, length: int = 512):
        return cls.model_validate({
            **alg.config.params(),
            'k': Base64(os.urandom(length // 8))
        })

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return all([
            alg.use == 'sig',
            alg.dig in {'sha256', 'sha384', 'sha512'}
        ])

    def is_asymmetric(self) -> bool:
        return False

    def sign(
        self,
        message: bytes,
        alg: JSONWebAlgorithm | None = None
    ) -> AwaitableBytes:
        alg = alg or self.alg
        assert alg is not None
        assert alg.dig is not None
        m = hmac.new(self.k, message, alg.dig)
        return AwaitableBytes(m.digest())

    def verify(
        self,
        signature: bytes,
        message: bytes
    ):
        m = self.sign(message, self.alg)
        return AwaitableBool(secrets.compare_digest(bytes(m), signature))