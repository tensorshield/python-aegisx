from typing import Any
from typing import Awaitable
from typing import Callable

import pytest
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JSONWebToken
from aegisx.ext.jose.models import JSONWebKeySet
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.types import JSONWebAlgorithm


__all__: list[str] = [
    'test_compat_jwt_jws_their_signature_our_verification',
    'test_compat_bytes_jws_their_signature_our_verification',
    'test_compat_jwt_jws_our_signature_their_verification',
    #'test_compat_bytes_jws_our_signature_their_verification',
    'test_compat_jwt_jwe_their_encryption_our_decryption',
    'test_compat_jwt_jwe_their_encryption_our_decryption_direct',
    'test_compat_jwe_our_encryption_their_decryption',
    'test_compat_jwe_our_encryption_their_decryption_direct',
    'JWSVerify',
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
    JSONWebAlgorithm.validate('A128CBC-HS256'),
    JSONWebAlgorithm.validate('A192CBC-HS384'),
    JSONWebAlgorithm.validate('A256CBC-HS512'),
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


@pytest.mark.parametrize("second", [None, JSONWebKey.generate(alg='ES256')])
@pytest.mark.parametrize("alg,kid", JWS_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jws_their_signature_our_verification(
    jws_factory: JWSFactory,
    alg: JSONWebAlgorithm,
    kid: str,
    jwks: JSONWebKeySet,
    second: JSONWebKey | None
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    validator = TokenValidator[JSONWebToken](
        JSONWebToken,
        jwks=jwks,
        issuer='foo'
    )
    signers =  [key]
    if second is not None:
        signers.append(key)
    serialized = await jws_factory(alg, signers, {'iss': 'foo'})
    jwt = await validator.validate(serialized)
    assert jwt.iss == 'foo'


@pytest.mark.parametrize("alg,kid", JWS_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_bytes_jws_their_signature_our_verification(
    jws_factory: JWSFactory,
    alg: JSONWebAlgorithm,
    kid: str,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    validator = TokenValidator(jwks=jwks)
    serialized = await jws_factory(alg, [key], b'Hello world!')
    buf = await validator.validate(serialized)
    assert buf == b'Hello world!', buf


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
    keys = [key]
    jws = await TokenBuilder(JSONWebToken)\
        .update(iss='https://test.tensorshield.ai')\
        .sign(key)\
        .build()
    await jws_verify(alg, keys, jws)


@pytest.mark.parametrize("alg,kid", JWS_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_bytes_jws_our_signature_their_verification(
    jws_verify: JWSVerify,
    alg: JSONWebAlgorithm,
    kid: str,
    jwks: JSONWebKeySet
):
    key = jwks.get(kid)
    if key is None:
        pytest.fail(f"No test key '{kid}' specified for {alg}.")
    keys = [key]
    jws = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(key)\
        .build()
    await jws_verify(alg, keys, jws)


@pytest.mark.parametrize("alg,kid", JWE_ALGORITHMS)
@pytest.mark.parametrize("enc", JWE_CEK_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jwe_their_encryption_our_decryption(
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
        jwe_factory=jwe_factory,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


@pytest.mark.parametrize("alg,enc,kid", JWE_DIRECT_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwt_jwe_their_encryption_our_decryption_direct(
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
        decrypt_jwe=decrypt_jwe,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


@pytest.mark.parametrize("alg,enc,kid", JWE_DIRECT_ALGORITHMS)
@pytest.mark.asyncio
async def test_compat_jwe_our_encryption_their_decryption_direct(
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
        decrypt_jwe=decrypt_jwe,
        alg=alg,
        kid=kid,
        enc=enc,
        jwks=jwks
    )


async def _test_compat_jwe_our_encryption_their_decryption(
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
    payload = b'Hello world!'
    jwe = await TokenBuilder(bytes)\
        .payload(payload)\
        .encrypt(key, enc=enc)\
        .build()
    assert isinstance(jwe, str)
    deserialized = await decrypt_jwe(jwe, [key])
    assert deserialized == payload, f'{repr(payload)} != {repr(deserialized)}'


async def _test_compat_jwt_jwe_their_encryption_our_decryption(
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
    serialized, ipt = await jwe_factory(alg, enc, [key], {'iss': 'https://jose.example'})
    opt = await TokenValidator(bytes, key=key)\
        .validate(serialized)
    assert ipt == opt, f'{repr(ipt)} != {repr(opt)}'
    jwt = JSONWebToken.model_validate_json(b64decode(opt))
    assert jwt.iss == 'https://jose.example'