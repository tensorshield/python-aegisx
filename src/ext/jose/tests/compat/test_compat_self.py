from typing import Any

import pytest
from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JSONWebToken
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
        await TokenValidator(JSONWebToken | bytes)\
            .validate(serialized)
        return True

    return f


@pytest.fixture
def jws_factory():
    async def f(alg: JSONWebAlgorithm, signers: list[JSONWebKey], claims: dict[str, Any] | bytes):
        builder = TokenBuilder(JSONWebToken | bytes)
        if isinstance(claims, dict):
            builder.update(claims)
        if isinstance(claims, bytes):
            builder.payload(claims)
        for signer in signers:
            builder.sign(signer)
        return await builder.build()
    return f

@pytest.fixture
def jwe_factory():
    async def f(
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        recipients: list[JSONWebKey],
        payload: dict[str, Any] | bytes
    ):
        match isinstance(payload, bytes):
            case True:
                assert isinstance(payload, bytes)
                builder = TokenBuilder(bytes)\
                    .payload(payload)
            case False:
                assert isinstance(payload, dict)
                builder = TokenBuilder(JSONWebToken)\
                    .update(payload)
                payload = b64encode_json(payload) # TODO
        for recipient in recipients:
            builder.encrypt(recipient, enc=enc)
        return await builder.build(), builder.plaintext

    return f

@pytest.fixture
def decrypt_jwe():
    async def f(serialized: bytes, recipients: list[JSONWebKey]):
        return await TokenValidator(bytes, keys=recipients)\
            .validate(serialized)

    return f
