import pytest

from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken


@pytest.mark.asyncio
async def test_encrypt_symmetric():
    key = JSONWebKey.generate(alg='A128GCM')
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .encrypt(key, enc='A128GCM')\
        .build()
    print(token)


@pytest.mark.asyncio
async def test_encrypt_asymmetric():
    key = JSONWebKey.generate(alg='ECDH-ES+A128KW', crv='P-256')
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .encrypt(key, enc='A128GCM')\
        .build()
    print(token)


@pytest.mark.asyncio
async def test_decrypt_symmetric():
    key = JSONWebKey.generate(alg='A128GCM')
    assert key.use == 'enc'
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .encrypt(key, enc='A128GCM')\
        .build()

    pt = await TokenValidator(bytes, key=key)\
        .validate(token)
    assert pt == b'Hello world!'


@pytest.mark.asyncio
async def test_decrypt_asymmetric():
    key = JSONWebKey.generate(alg='ECDH-ES+A128KW', crv='P-256')
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .encrypt(key, enc='A128GCM')\
        .build()

    pt = await TokenValidator(bytes, key=key)\
        .validate(token)
    assert pt == b'Hello world!'


@pytest.mark.asyncio
async def test_decrypt_jwt():
    key = JSONWebKey.generate(alg='A128GCM')
    assert key.use == 'enc'
    token = await TokenBuilder(JSONWebToken)\
        .update(iss='https://foo.com')\
        .encrypt(key, enc='A128GCM')\
        .build()

    pt = await TokenValidator(JSONWebToken, key=key)\
        .validate(token)
    assert pt.iss == 'https://foo.com'