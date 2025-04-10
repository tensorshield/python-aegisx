from typing import Any

import pydantic
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64
try:
    scalecodec: Any
    sr25519: Any
    import scalecodec
    import sr25519
except ImportError:
    from libcanonical.code import MissingDependency
    scalecodec = sr25519 = MissingDependency(
        "To use JSON Web Key (JWK) with Sr25519 the scalecodec "
        "and sr25519 modules must be installed."
    )

from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeysr25519public import JSONWebKeySR25519Public


class JSONWebKeySR25519Private(JSONWebKeySR25519Public):
    model_config = {
        'title': 'SrDSA Private Key'
    }

    d: Base64 = pydantic.Field(
        default=...,
        max_length=64,
        min_length=64,
        title="Private key",
        description=(
            "Contains the private key encoded using the base64url encoding. "
            "This parameter MUST NOT be present for public keys."
        )
    )

    @classmethod
    def generate(
        cls,
        alg: JSONWebAlgorithm,
        ss58_format: int = 42,
    ) -> 'JSONWebKeySR25519Private':
        k = Ed25519PrivateKey.generate()
        public, private = sr25519.pair_from_seed(k.private_bytes_raw())
        kid = scalecodec.ss58_encode(public, ss58_format=ss58_format)
        return cls.model_validate({
            **alg.config.params(),
            'crv': 'Sr25519',
            'kid': kid,
            'x': Base64(public),
            'd': Base64(private)
        })

    @classmethod
    def create_from_private_key(cls, k: str | bytes, ss58_format: int = 42):
        if isinstance(k, str) and str.startswith(k, '0x'):
            k = str.replace(k, '0x', '')
        if isinstance(k, str):
            k = bytes.fromhex(k)
        public = sr25519.public_from_secret_key(k)
        private = k
        return cls.model_validate({
            'kty': 'OKP',
            'alg': 'EdDSA',
            'kid': scalecodec.ss58_encode(public, ss58_format=ss58_format),
            'crv': 'Sr25519',
            'use': 'sig',
            'key_ops': {'sign', 'verify'},
            'x': Base64(public),
            'd': Base64(private)
        })

    @classmethod
    def create_from_seed(cls, seed: str | bytes, ss58_format: int = 42):
        if isinstance(seed, str) and str.startswith(seed, '0x'):
            seed = str.replace(seed, '0x', '')
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        public, private = sr25519.pair_from_seed(seed)
        kid = scalecodec.ss58_encode(public, ss58_format=ss58_format)
        return cls.model_validate({
            'kty': 'OKP',
            'alg': 'EdDSA',
            'kid': kid,
            'crv': 'Sr25519',
            'use': 'sig',
            'key_ops': {'sign', 'verify'},
            'x': Base64(public),
            'd': Base64(private)
        })

    def sign(
        self,
        message: bytes,
        alg: JSONWebAlgorithm | None = None
    ) -> AwaitableBytes:
        return AwaitableBytes(sr25519.sign((self.x, self.d), message))