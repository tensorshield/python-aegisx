from typing import Any
from typing import Literal

import pydantic
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeyedwardscurvepublic import JSONWebKeyEdwardsCurvePublic


class JSONWebKeyEdwardsCurvePrivate(JSONWebKeyEdwardsCurvePublic):
    model_config = {
        'title': 'EdDSA Private Key'
    }

    d: Base64 = pydantic.Field(
        default=...,
        title="Private key",
        description=(
            "Contains the private key encoded using the base64url encoding. "
            "This parameter MUST NOT be present for public keys."
        )
    )

    @classmethod
    def generate(
        cls,
        alg: JSONWebAlgorithm | str,
        crv: Literal['Ed448', 'Ed25519', 'X448', 'X25519'],
        **kwargs: Any
    ) -> 'JSONWebKeyEdwardsCurvePrivate':
        if not isinstance(alg, JSONWebAlgorithm):
            alg = JSONWebAlgorithm.validate(alg)
        match crv:
            case 'Ed448':
                k = Ed448PrivateKey.generate()
            case 'Ed25519':
                k = Ed25519PrivateKey.generate()
            case 'X448':
                k = X448PrivateKey.generate()
            case 'X25519':
                k = X25519PrivateKey.generate()
        return cls.model_validate({
            **kwargs,
            **alg.config.params(),
            'kty': 'OKP',
            'crv': crv,
            'x': Base64(k.public_key().public_bytes_raw()),
            'd': Base64(k.private_bytes_raw())
        })

    @property
    def private_key(self):
        match self.crv:
            case 'Ed448':
                return Ed448PrivateKey.from_private_bytes(self.d)
            case 'Ed25519':
                return Ed25519PrivateKey.from_private_bytes(self.d)
            case 'X448':
                return X448PrivateKey.from_private_bytes(self.d)
            case 'X25519':
                return X25519PrivateKey.from_private_bytes(self.d)

    def decrypt(self, result: EncryptionResult) -> AwaitableBytes:
        assert result.epk is not None
        assert result.alg.config.length
        if not result.epk.crv == self.crv:
            raise TypeError(f"Curve mismatch: {result.epk.crv}")
        if not result.alg.wrap:
            raise TypeError(
                f"Not a wrapping algorithm: {result.alg}. For direct encryption "
                f"use {type(self).__name__}.derive_cek()."
            )
        derived = self.derive(
            alg=result.alg,
            enc=result.alg.wrap,
            public=result.epk.public_key,
            private=self.private_key,
            apu=result.apu,
            apv=result.apv
        )
        match result.alg.config.mode == 'KEY_AGREEMENT_WITH_KEY_WRAPPING':
            case True:
                return AwaitableBytes(aes_key_unwrap(derived, result.ct))
            case False:
                return AwaitableBytes(derived)

    def sign(
        self,
        message: bytes,
        alg: JSONWebAlgorithm | None = None
    ) -> AwaitableBytes:
        assert isinstance(self.private_key, (Ed448PrivateKey, Ed25519PrivateKey))
        return AwaitableBytes(self.private_key.sign(message))