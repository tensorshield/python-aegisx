import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aegisx.core.crypto import Algorithm
from aegisx.types import EllipticCurve


RSA_NAMED_ALGORITHMS = [
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
    #"RSA-OAEP-512",
]

SYMMETRIC_NAMED_ALGORITHMS = [
    'A128KW',
    'A192KW',
    'A256KW',
    'A128GCMKW',
    'A192GCMKW',
    'A256GCMKW',
    'A128GCM',
    'A192GCM',
    'A256GCM',
    'A128CBC-HS256',
    'A192CBC-HS384',
    'A256CBC-HS512',
]

ECDH_NAMED_ALGORITHMS = [
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
]


@pytest.mark.parametrize("name", [
    *RSA_NAMED_ALGORITHMS,
    *SYMMETRIC_NAMED_ALGORITHMS
])
def test_fromstring(name: str):
    alg = Algorithm.model_validate(name)
    assert alg.root.name == name


@pytest.mark.parametrize("name", RSA_NAMED_ALGORITHMS)
def test_rsa_encrypt_named(
    rsa_key: rsa.RSAPrivateKey,
    name: str
):
    alg = Algorithm.model_validate(name)
    key = rsa_key
    ct = b'Hello world!'
    result = alg.encrypt(key.public_key(), ct)
    assert alg.decrypt(key, result) == ct


@pytest.mark.parametrize("name", SYMMETRIC_NAMED_ALGORITHMS)
def test_sym_encrypt_named(
    name: str
):
    alg = Algorithm.model_validate(name)
    key = alg.generate()
    pt = os.urandom(16)
    result = alg.encrypt(key, pt)
    assert alg.decrypt(key, result) == pt


@pytest.mark.parametrize("aad", [None, b'Hello world!'])
@pytest.mark.parametrize("name", [
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
])
def test_sym_encrypt_aad_named(
    name: str,
    aad: bytes | None
):
    alg = Algorithm.model_validate(name)
    key = alg.generate()
    pt = os.urandom(16)
    result = alg.encrypt(key, pt, aad=aad)
    assert alg.decrypt(key, result) == pt


@pytest.mark.parametrize("name", ECDH_NAMED_ALGORITHMS)
@pytest.mark.parametrize("crv", EllipticCurve.__cryptography_curves__.values())
def test_ecdh_ec_encrypt_named(
    name: str,
    crv: type[ec.EllipticCurve]
):
    alg = Algorithm.model_validate(name)
    length = 32
    if alg.wrp:
        length = None
    skey = ec.generate_private_key(crv())
    rkey = ec.generate_private_key(crv())
    epk = alg.epk(skey)
    s1 = alg.derive(epk, rkey.public_key(), b'Hello world!', length=length)
    s2 = alg.derive(rkey, epk.public_key(), b'Hello world!', length=length)
    assert s1.k == s2.k


@pytest.mark.parametrize("name", ECDH_NAMED_ALGORITHMS)
def test_ecdh_x448_encrypt_named(name: str):
    alg = Algorithm.model_validate(name)
    length = 32
    if alg.wrp:
        length = None
    skey = X448PrivateKey.generate()
    rkey = X448PrivateKey.generate()
    epk = alg.epk(skey)
    s1 = alg.derive(epk, rkey.public_key(), b'Hello world!', length=length)
    s2 = alg.derive(rkey, epk.public_key(), b'Hello world!', length=length)
    assert s1.k == s2.k


@pytest.mark.parametrize("name", ECDH_NAMED_ALGORITHMS)
def test_ecdh_x25519_encrypt_named(name: str):
    alg = Algorithm.model_validate(name)
    length = 32
    if alg.wrp:
        length = None
    skey = X25519PrivateKey.generate()
    rkey = X25519PrivateKey.generate()
    epk = alg.epk(skey)
    s1 = alg.derive(epk, rkey.public_key(), b'Hello world!', length=length)
    s2 = alg.derive(rkey, epk.public_key(), b'Hello world!', length=length)
    assert s1.k == s2.k


@pytest.fixture
def rsa_key():
    return rsa.generate_private_key(key_size=1024, public_exponent=65537)