import os
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aegisx.core.crypto import Algorithm


SUPPORTED_HASHES = ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b512', 'blake2s256']


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(key_size=1024, public_exponent=65537)


@pytest.mark.parametrize("params", [
    {'name': 'ES256'},
    {'name': 'ES384'},
    {'name': 'ES512'},
    {'name': 'BS256'},
    {'name': 'BS384'},
    {'name': 'BS512'},
    {'name': 'ES256-SHA3'},
    {'name': 'ES384-SHA3'},
    {'name': 'ES512-SHA3'},
    {'name': 'BS256-SHA3'},
    {'name': 'BS384-SHA3'},
    {'name': 'BS512-SHA3'},
])
def test_elliptic_curve_sign_with_named_algorithm(
    params: dict[str, Any]
):
    msg = b'Hello world!'
    alg = Algorithm.model_validate({**params, 'use': 'sig'})
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=False)
    assert alg.verify(key.public_key(), sig, msg, prehashed=False)


@pytest.mark.parametrize("crv", [
    "P-256",
    "P-384",
    "P-521",
    "B-256",
    "B-384",
    "B-512",
    "P-256K",
])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", SUPPORTED_HASHES)
def test_elliptic_curve_sign_dynamic(
    crv: str,
    dig: str,
    prehashed: bool
):
    alg = Algorithm.model_validate({
        'crv': crv,
        'dig': dig,
        'use': 'sig',
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=prehashed)
    assert alg.verify(key.public_key(), sig, msg, prehashed=prehashed)


@pytest.mark.parametrize("crv", [
    "P-256",
    "P-384",
    "P-521",
    "B-256",
    "B-384",
    "B-512",
    "P-256K",
])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", SUPPORTED_HASHES)
def test_elliptic_curve_sign_evil_message(
    crv: str,
    dig: str,
    prehashed: bool
):
    alg = Algorithm.model_validate({
        'crv': crv,
        'dig': dig,
        'use': 'sig'
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=prehashed)
    evil = b'Hello Mars!'
    if prehashed:
        assert alg.dig
        evil = alg.dig.digest(evil)
    assert not alg.verify(key.public_key(), sig, evil, prehashed=prehashed)


@pytest.mark.parametrize("crv", [
    "P-256",
    "P-384",
    "P-521",
    "B-256",
    "B-384",
    "B-512",
    "P-256K",
])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", SUPPORTED_HASHES)
def test_elliptic_curve_sign_evil_signature(
    crv: str,
    dig: str,
    prehashed: bool
):
    alg = Algorithm.model_validate({
        'crv': crv,
        'dig': dig,
        'use': 'sig'
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=prehashed)
    assert not alg.verify(key.public_key(), os.urandom(len(sig)), msg, prehashed=prehashed)


@pytest.mark.parametrize("params", [
    {'name': 'RS256'},
    {'name': 'RS384'},
    {'name': 'RS512'},
    {'name': 'PS256'},
    {'name': 'PS384'},
    {'name': 'PS512'},
    {'name': 'RS256-SHA3'},
    {'name': 'RS384-SHA3'},
    {'name': 'RS512-SHA3'},
    {'name': 'PS256-SHA3'},
    {'name': 'PS384-SHA3'},
    {'name': 'PS512-SHA3'},
])
def test_rsa_with_named_algorithm(
    rsa_key: rsa.RSAPrivateKey,
    params: dict[str, Any]
):
    key = rsa_key
    msg = b'Hello world!'
    alg = Algorithm.model_validate({**params, 'use': 'sig'})
    sig = alg.sign(key, msg, prehashed=False)
    assert alg.verify(key.public_key(), sig, msg, prehashed=False)


@pytest.mark.parametrize("pad", ["EMSA-PSS", "EMSA-PKCS1-v1_5"])
@pytest.mark.parametrize("kty", ["RSA"])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", set(SUPPORTED_HASHES) - {'blake2b512', 'blake2s256'})
def test_rsa_sign_dynamic(
    rsa_key: rsa.RSAPrivateKey,
    pad: str,
    dig: str,
    kty: str,
    prehashed: bool
):
    key = rsa_key
    alg = Algorithm.model_validate({
        'dig': dig,
        'pad': pad,
        'kty': kty,
        'use': 'sig'
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    sig = alg.sign(key, msg, prehashed=prehashed)
    assert alg.verify(key.public_key(), sig, msg, prehashed=prehashed)


@pytest.mark.parametrize("pad", ["EMSA-PSS", "EMSA-PKCS1-v1_5"])
@pytest.mark.parametrize("kty", ["RSA"])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", set(SUPPORTED_HASHES) - {'blake2b512', 'blake2s256'})
def test_rsa_sign_evil_message(
    rsa_key: rsa.RSAPrivateKey,
    pad: str,
    dig: str,
    kty: str,
    prehashed: bool
):
    key = rsa_key
    alg = Algorithm.model_validate({
        'dig': dig,
        'pad': pad,
        'kty': kty,
        'use': 'sig'
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    sig = alg.sign(key, msg, prehashed=prehashed)
    evil = b'Hello Mars!'
    if prehashed:
        assert alg.dig
        evil = alg.dig.digest(evil)
    assert not alg.verify(key.public_key(), sig, evil, prehashed=prehashed)


@pytest.mark.parametrize("pad", ["EMSA-PSS", "EMSA-PKCS1-v1_5"])
@pytest.mark.parametrize("kty", ["RSA"])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", set(SUPPORTED_HASHES) - {'blake2b512', 'blake2s256'})
def test_rsa_sign_evil_signature(
    rsa_key: rsa.RSAPrivateKey,
    pad: str,
    dig: str,
    kty: str,
    prehashed: bool
):
    key = rsa_key
    alg = Algorithm.model_validate({
        'dig': dig,
        'pad': pad,
        'kty': kty,
        'use': 'sig'
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    sig = alg.sign(key, msg, prehashed=prehashed)
    assert not alg.verify(key.public_key(), os.urandom(len(sig)), msg, prehashed=prehashed)


@pytest.mark.parametrize("crv", [
    "Ed25519",
    "Ed448",
    "Sr25519"
])
def test_eddsa_sign_dynamic(
    crv: str,
):
    alg = Algorithm.model_validate({
        'alg': 'EdDSA',
        'crv': crv,
        'use': 'sig'
    })
    msg = b'Hello world!'
    key = alg.generate()
    sig = alg.sign(key, msg)
    assert alg.verify(key.public_key(), sig, msg)


@pytest.mark.parametrize("crv", [
    "Ed25519",
    "Ed448",
    "Sr25519"
])
def test_eddsa_sign_evil_message(crv: str):
    alg = Algorithm.model_validate({
        'alg': 'EdDSA',
        'crv': crv,
        'use': 'sig'
    })
    msg = b'Hello world!'
    key = alg.generate()
    sig = alg.sign(key, msg)
    assert not alg.verify(key.public_key(), sig, b'Hello Mars!')


@pytest.mark.parametrize("crv", [
    "Ed25519",
    "Ed448",
    "Sr25519"
])
def test_eddsa_sign_evil_signature(crv: str):
    alg = Algorithm.model_validate({
        'alg': 'EdDSA',
        'crv': crv,
        'use': 'sig'
    })
    msg = b'Hello world!'
    key = alg.generate()
    sig = alg.sign(key, msg)
    assert not alg.verify(key.public_key(), os.urandom(len(sig)), msg)


@pytest.mark.parametrize("params", [
    {'name': 'HS256'},
    {'name': 'HS384'},
    {'name': 'HS512'},
    {'name': 'HB256'},
    {'name': 'HB512'},
    {'name': 'HS256-SHA3'},
    {'name': 'HS384-SHA3'},
    {'name': 'HS512-SHA3'},
])
def test_symmetric_sign_with_named_algorithm(
    params: dict[str, Any]
):
    msg = b'Hello world!'
    alg = Algorithm.model_validate({**params, 'use': 'sig'})
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=False)
    assert alg.verify(key, sig, msg, prehashed=False)