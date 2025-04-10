from typing import Any

import pytest
from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JSONWebEncryption
from aegisx.ext.jose.models import JSONWebSignature
from aegisx.ext.jose.types import JWSCompactEncoded
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.testing.compat import *


@pytest.fixture
def supported_curves():
    return {
        'P-256',
        'P-256K',
        'P-384',
        'P-521',
        'Ed448',
        'Ed25519',
        'X448',
        'X25519',
        'Sr25519',
    }


@pytest.fixture
def jws_verify():
    async def f(
        alg: JSONWebAlgorithm,
        signers: list[JSONWebKey],
        serialized: str
    ):
        jws = JSONWebSignature(JWSCompactEncoded(serialized))
        return await jws.verify(*signers)

    return f


@pytest.fixture
def jws_factory():
    async def f(alg: JSONWebAlgorithm, signers: list[JSONWebKey], claims: dict[str, Any]):
        jws = JSONWebSignature(claims)
        for signer in signers:
            await jws.sign(signer)
        return jws.serialize()
    return f

@pytest.fixture
def jwe_factory():
    async def factory(
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm | None,
        signers: list[JSONWebKey],
        payload: dict[str, Any] | bytes
    ) -> tuple[str, bytes]:
        if isinstance(payload, dict):
            payload = b64encode_json(payload)
        jwe = JSONWebEncryption(payload)
        jwe.encrypt(signers[0])
        return str(await jwe), payload

    return factory


@pytest.fixture
def decrypt_jwe():
    async def f(serialized: str, keys: list[JSONWebKey]):
        key = keys[0]
        jwe = JSONWebEncryption.model_validate(serialized)
        await jwe.decrypt(key)
        return jwe.plaintext

    return f