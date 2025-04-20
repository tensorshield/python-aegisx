from typing import cast
from typing import Any
from typing import Literal

import pydantic
from libcanonical.types import AwaitableBool
from libcanonical.types import Base64
try:
    sr25519: Any
    scalecodec: Any
    import sr25519
    import scalecodec.utils.ss58 # type: ignore
except ImportError:
    from libcanonical.code import MissingDependency
    scalecodec = sr25519 = MissingDependency(
        "To use JSON Web Key (JWK) with Sr25519 the scalecodec "
        "and sr25519 modules must be installed."
    )

from aegisx.ext.jose.types._jsonwebalgorithm import JSONWebAlgorithm

from ._jsonwebkeybase import JSONWebKeyBase


class JSONWebKeySR25519Public(JSONWebKeyBase[
    Literal['OKP'],
    Literal['sign', 'verify']
]):
    model_config = {
        'title': 'SrDSA Public Key'
    }

    thumbprint_claims = ["crv", "kty", "x"]

    crv: Literal['Sr25519'] = pydantic.Field(
        default=...,
        title="Curve",
        description=(
            "The `crv` (curve) parameter identifies the "
            "cryptographic curve used with the key."
        )
    )

    x: Base64 = pydantic.Field(
        default=...,
        title="Public key",
        max_length=32,
        min_length=32,
        description=(
            "Contains the public key encoded using the base64url encoding."
        )
    )

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return alg == 'EdDSA'

    @pydantic.model_validator(mode='before')
    def preprocess_values(cls, value: Any | dict[str, Any]) -> dict[str, Any]:
        if isinstance(value, dict):
            value = cast(dict[str, Any], value)
            if value.get('ss58_address'):
                public_key = scalecodec.utils.ss58.ss58_decode(
                    value.pop('ss58_address'),
                    valid_ss58_format=value.pop('ss58_format', None) or 42
                )
                value.update({
                    'kty': 'OKP',
                    'alg': 'EdDSA',
                    'crv': 'Sr25519',
                    'use': 'sig',
                    'key_ops': {'verify'},
                    'x': Base64(bytes.fromhex(public_key))
                })
        return value

    @pydantic.model_validator(mode='after')
    def postprocess(self):
        if self.kid is None:
            self.kid = scalecodec.ss58_encode(bytes(self.x), ss58_format=42)
        return self

    def get_public_key(self) -> 'JSONWebKeySR25519Public':
        return JSONWebKeySR25519Public.model_validate({
            **self.model_dump(exclude={'d'}),
            'key_ops': (self.key_ops & {'verify', 'encrypt'}) if self.key_ops else None
        })

    def is_asymmetric(self) -> bool:
        return True

    def verify(
        self,
        signature: bytes,
        message: bytes,
        alg: JSONWebAlgorithm | None = None
    ) -> AwaitableBool:
        try:
            return AwaitableBool(sr25519.verify(signature, message, self.x))
        except ValueError:
            return AwaitableBool(False)