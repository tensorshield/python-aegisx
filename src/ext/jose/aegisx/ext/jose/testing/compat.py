from typing import Any
from typing import Awaitable
from typing import Callable

import pytest
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose.models import JSONWebEncryption
from aegisx.ext.jose.models import JSONWebToken
from aegisx.ext.jose.models import JSONWebKeySet
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JSONWebSignature
from aegisx.ext.jose.types import JSONWebAlgorithm


__all__: list[str] = [
    'test_compat_jwt_jws_their_signature_our_verification',
    'test_compat_jwt_jws_our_signature_their_verification',
    'test_compat_jwt_jwe_their_encryption_our_decryption',
    'test_compat_jwt_jwe_their_encryption_our_decryption_direct',
    'test_compat_jwe_our_encryption_their_decryption',
    'test_compat_jwe_our_encryption_their_decryption_direct',
    'JWSFactory',
]

JWSFactory = Callable[
    [
        JSONWebAlgorithm,
        list[JSONWebKey],
        dict[str, Any] | bytes
    ],
    Awaitable[str]
]

JWSVerify = Callable[
    [
        JSONWebAlgorithm,
        list[JSONWebKey],
        str
    ],
    Awaitable[bool]
]


JWE_ALGORITHMS = [
    (JSONWebAlgorithm.validate('RSA-OAEP-256'), 'test-jwe-rsa-oaep-256'),
    (JSONWebAlgorithm.validate('RSA-OAEP-384'), 'test-jwe-rsa-oaep-384'),
    (JSONWebAlgorithm.validate('RSA-OAEP-512'), 'test-jwe-rsa-oaep-512'),
    (JSONWebAlgorithm.validate('A128KW'), 'test-jwe-a128kw'),
    (JSONWebAlgorithm.validate('A192KW'), 'test-jwe-a192kw'),
    (JSONWebAlgorithm.validate('A256KW'), 'test-jwe-a256kw'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-default'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-default'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-default'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-p-521'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-p-521'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-p-521'),
    (JSONWebAlgorithm.validate('A128GCMKW'), 'test-jwe-a128gcmkw'),
    (JSONWebAlgorithm.validate('A192GCMKW'), 'test-jwe-a192gcmkw'),
    (JSONWebAlgorithm.validate('A256GCMKW'), 'test-jwe-a256gcmkw'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES+A128KW'), 'test-jwe-ecdh-es-a128-kw-x25519'),
    (JSONWebAlgorithm.validate('ECDH-ES+A192KW'), 'test-jwe-ecdh-es-a192-kw-x25519'),
    (JSONWebAlgorithm.validate('ECDH-ES+A256KW'), 'test-jwe-ecdh-es-a256-kw-x25519'),
]

JWE_DIRECT_ALGORITHMS = [
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-p-256'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-p-256'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-p-256'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-p-256'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-p-256'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-p-256'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-p-256k'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-p-256k'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-p-256k'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-p-256k'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-p-384'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-p-384'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-p-384'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-p-384'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-p-521'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-p-521'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-p-521'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-p-521'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-p-521'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-p-521'),
    (JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-dir-a128'),
    (JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-dir-a192'),
    (JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-dir-a256'),
    #(JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-dir-256b'),
    #(JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-dir-384b'),
    #(JSONWebAlgorithm.validate('dir'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-dir-512b'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-x448'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-x448'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-x448'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-x448'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128GCM'), 'test-jwe-ecdh-es-direct-x25519'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192GCM'), 'test-jwe-ecdh-es-direct-x25519'),
    (JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256GCM'), 'test-jwe-ecdh-es-direct-x25519'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A128CBC-HS256'), 'test-jwe-ecdh-es-direct-x25519'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A192CBC-HS384'), 'test-jwe-ecdh-es-direct-x25519'),
    #(JSONWebAlgorithm.validate('ECDH-ES'), JSONWebAlgorithm.validate('A256CBC-HS512'), 'test-jwe-ecdh-es-direct-x25519'),
]

JWE_CEK_ALGORITHMS = [
    #JSONWebAlgorithm.validate('A128CBC-HS256'),
    #JSONWebAlgorithm.validate('A192CBC-HS384'),
    #JSONWebAlgorithm.validate('A256CBC-HS512'),
    JSONWebAlgorithm.validate('A128GCM'),
    JSONWebAlgorithm.validate('A192GCM'),
    JSONWebAlgorithm.validate('A256GCM'),
]

JWS_ALGORITHMS = [
    (JSONWebAlgorithm('HS256'), 'test-jws-hs256'),
    (JSONWebAlgorithm('HS384'), 'test-jws-hs384'),
    (JSONWebAlgorithm('HS512'), 'test-jws-hs512'),
    (JSONWebAlgorithm('RS256'), 'test-jws-rs256'),
    (JSONWebAlgorithm('RS384'), 'test-jws-rs384'),
    (JSONWebAlgorithm('RS512'), 'test-jws-rs512'),
    (JSONWebAlgorithm('PS256'), 'test-jws-ps256'),
    (JSONWebAlgorithm('PS384'), 'test-jws-ps384'),
    (JSONWebAlgorithm('PS512'), 'test-jws-ps512'),
    (JSONWebAlgorithm('ES256'), 'test-jws-es256'),
    (JSONWebAlgorithm('ES384'), 'test-jws-es384'),
    (JSONWebAlgorithm('ES512'), 'test-jws-es512'),
    (JSONWebAlgorithm('ES256K'), 'test-jws-es256k'),
    (JSONWebAlgorithm('EdDSA'), 'test-jws-ed448'),
    (JSONWebAlgorithm('EdDSA'), 'test-jws-ed25519'),
    (JSONWebAlgorithm('EdDSA'), 'test-jws-sr25519'),
]


@pytest.mark.parametrize("alg,kid", JWS_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jws_their_signature_our_verification(
    jws_factory: JWSFactory,
    alg: JSONWebAlgorithm,
    kid: str,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    serialized = await jws_factory(alg, [key], {'iss': 'foo'})
    jws = JSONWebSignature.model_validate(serialized)
    assert await jws.verify(key)


@pytest.mark.parametrize("alg,kid", JWS_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jws_our_signature_their_verification(
    jws_verify: JWSVerify,
    alg: JSONWebAlgorithm,
    kid: str,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    jws = JSONWebSignature({'foo': 'bar'})
    jws.sign(key)
    await jws_verify(alg, [key], str(await jws))


@pytest.mark.parametrize("alg,kid", JWE_ALGORITHMS)
@pytest.mark.parametrize("enc", JWE_CEK_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jwe_their_encryption_our_decryption(
    supported_curves: set[str],
    jwe_factory: Callable[
        [
            JSONWebAlgorithm,
            JSONWebAlgorithm,
            list[JSONWebKey],
            dict[str, Any] | bytes
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    return await _test_compat_jwt_jwe_their_encryption_our_decryption(
        supported_curves=supported_curves,
        jwe_factory=jwe_factory,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


@pytest.mark.parametrize("alg,enc,kid", JWE_DIRECT_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jwe_their_encryption_our_decryption_direct(
    supported_curves: set[str],
    jwe_factory: Callable[
        [
            JSONWebAlgorithm,
            JSONWebAlgorithm,
            list[JSONWebKey],
            dict[str, Any] | bytes
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    return await _test_compat_jwt_jwe_their_encryption_our_decryption(
        supported_curves=supported_curves,
        jwe_factory=jwe_factory,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


@pytest.mark.parametrize("alg,kid", JWE_ALGORITHMS)
@pytest.mark.parametrize("enc", JWE_CEK_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwe_our_encryption_their_decryption(
    supported_curves: set[str],
    decrypt_jwe: Callable[
        [
            str,
            list[JSONWebKey],
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    await _test_compat_jwe_our_encryption_their_decryption(
        supported_curves=supported_curves,
        decrypt_jwe=decrypt_jwe,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


@pytest.mark.parametrize("alg,enc,kid", JWE_DIRECT_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwe_our_encryption_their_decryption_direct(
    supported_curves: set[str],
    decrypt_jwe: Callable[
        [
            str,
            list[JSONWebKey],
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    await _test_compat_jwe_our_encryption_their_decryption(
        supported_curves=supported_curves,
        decrypt_jwe=decrypt_jwe,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


async def _test_compat_jwe_our_encryption_their_decryption(
    supported_curves: set[str],
    decrypt_jwe: Callable[
        [
            str,
            list[JSONWebKey],
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    if key.crv and key.crv not in supported_curves:
        pytest.skip(f"Curve {key.crv} not supported by implementation.")
    payload = b'Hello world!'
    jwe = JSONWebEncryption(payload)
    jwe.encrypt(key, enc=JSONWebAlgorithm.validate(enc))
    deserialized = await decrypt_jwe(str(await jwe), [key])
    assert deserialized == payload, f'{repr(payload)} != {repr(deserialized)}'


async def _test_compat_jwt_jwe_their_encryption_our_decryption(
    supported_curves: set[str],
    jwe_factory: Callable[
        [
            JSONWebAlgorithm,
            JSONWebAlgorithm,
            list[JSONWebKey],
            dict[str, Any] | bytes
        ],
        Awaitable[str]
    ],
    alg: JSONWebAlgorithm,
    kid: str,
    enc: JSONWebAlgorithm,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    if key.crv and key.crv not in supported_curves:
        pytest.skip(f"Curve {key.crv} not supported by implementation.")
    serialized, ipt = await jwe_factory(alg, enc, [key], {'iss': 'https://jose.example'})
    jwe = JSONWebEncryption.model_validate(serialized)
    opt = await jwe.decrypt(key)
    assert opt == ipt
    jwt = JSONWebToken.model_validate_json(b64decode(opt))
    assert jwt.iss == 'https://jose.example'