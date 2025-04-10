import os
import tempfile

import pytest

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JSONWebKeySet
from aegisx.ext.jose.models import JSONWebKeySR25519Private


RSA_SIGNING_ALGORITHMS: list[str] = [
    JSONWebAlgorithm.validate('RS256'),
    JSONWebAlgorithm.validate('RS384'),
    JSONWebAlgorithm.validate('RS512'),
    JSONWebAlgorithm.validate('PS256'),
    JSONWebAlgorithm.validate('PS384'),
    JSONWebAlgorithm.validate('PS512'),
]

EC_SIGNING_ALGORITHMS: list[str] = [
    JSONWebAlgorithm.validate('ES256'),
    JSONWebAlgorithm.validate('ES256K'),
    JSONWebAlgorithm.validate('ES384'),
    JSONWebAlgorithm.validate('ES512'),
]

TEST_JWKS_PATH = os.path.join(tempfile.gettempdir(), 'canonical-jose-test-jwks.json')


@pytest.fixture(scope='session')
def sr25519_signing_key() -> JSONWebKeySR25519Private:
    k = JSONWebKey.generate(alg='EdDSA', crv='Sr25519').root # type: ignore
    assert k.kid
    return k # type: ignore


@pytest.fixture(scope='session')
def sig():
    return JSONWebKey.generate(alg='ES256')


@pytest.fixture(scope='function')
def enc():
    return JSONWebKey.generate(alg='A128GCM')


@pytest.fixture(scope='session')
def jwks_ec():
    return JSONWebKeySet.generate(['ES256', 'ES256K'])


@pytest.fixture(scope='session')
def jwks_rsa():
    return JSONWebKeySet.generate(['RS256'])


@pytest.fixture(scope='session')
def jwks():
    if not os.path.exists(TEST_JWKS_PATH):
        jwks = JSONWebKeySet(
            keys=[
                JSONWebKey.generate(alg='RS256', kid='sig1'),
                JSONWebKey.generate(alg='ES256', kid='sig2', crv='P-256'),
                JSONWebKey.generate(alg='HS256', kid='sig2', crv='P-256'),
                JSONWebKey.generate(alg='RS256', kid='sig-evil1'),
                JSONWebKey.generate(alg='ES256', kid='sig-evil2', crv='P-256'),
                JSONWebKey.generate(alg='HS256', kid='sig-evil3'),
                JSONWebKey.generate(alg='HS256', kid='test-jws-hs256'),
                JSONWebKey.generate(alg='HS384', kid='test-jws-hs384'),
                JSONWebKey.generate(alg='HS512', kid='test-jws-hs512'),
                JSONWebKey.generate(alg='RS256', kid='test-jws-rs256'),
                JSONWebKey.generate(alg='RS384', kid='test-jws-rs384'),
                JSONWebKey.generate(alg='RS512', kid='test-jws-rs512'),
                JSONWebKey.generate(alg='PS256', kid='test-jws-ps256'),
                JSONWebKey.generate(alg='PS384', kid='test-jws-ps384'),
                JSONWebKey.generate(alg='PS512', kid='test-jws-ps512'),
                JSONWebKey.generate(alg='ES256', kid='test-jws-es256', crv='P-256'),
                JSONWebKey.generate(alg='ES384', kid='test-jws-es384', crv='P-384'),
                JSONWebKey.generate(alg='ES512', kid='test-jws-es512', crv='P-521'),
                JSONWebKey.generate(alg='ES256K', kid='test-jws-es256k', crv='P-256K'),
                JSONWebKey.generate(alg='RSA-OAEP-256', kid='enc1'),
                JSONWebKey.generate(alg='RSA-OAEP-256', kid='enc2'),
                JSONWebKey.generate(alg='RSA-OAEP-256', kid='test-jwe-rsa-oaep-256'),
                JSONWebKey.generate(alg='RSA-OAEP-384', kid='test-jwe-rsa-oaep-384'),
                JSONWebKey.generate(alg='RSA-OAEP-512', kid='test-jwe-rsa-oaep-512'),
                JSONWebKey.generate(alg='A128KW', kid='test-jwe-a128kw'),
                JSONWebKey.generate(alg='A192KW', kid='test-jwe-a192kw'),
                JSONWebKey.generate(alg='A256KW', kid='test-jwe-a256kw'),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-a128', length=128),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-a192', length=192),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-a256', length=256),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-256b', length=256),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-384b', length=384),
                JSONWebKey.generate(alg='dir', kid='test-jwe-dir-512b', length=512),
                JSONWebKey.generate(alg='A128GCMKW', kid='test-jwe-a128gcmkw'),
                JSONWebKey.generate(alg='A192GCMKW', kid='test-jwe-a192gcmkw'),
                JSONWebKey.generate(alg='A256GCMKW', kid='test-jwe-a256gcmkw'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-p-256', crv='P-256'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-p-256k', crv='P-256K'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-p-384', crv='P-384'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-p-521', crv='P-521'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-default', crv='P-256'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-default', crv='P-256'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-default', crv='P-256'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-p-256k', crv='P-256K'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-p-256k', crv='P-256K'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-p-256k', crv='P-256K'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-p-384', crv='P-384'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-p-384', crv='P-384'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-p-384', crv='P-384'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-p-521', crv='P-521'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-p-521', crv='P-521'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-p-521', crv='P-521'),
                JSONWebKey.generate(alg='EdDSA', kid='test-jws-ed25519', crv='Ed25519'),
                JSONWebKey.generate(alg='EdDSA', kid='test-jws-ed448', crv='Ed448'),
                JSONWebKey.generate(alg='EdDSA', kid='test-jws-sr25519', crv='Sr25519'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-x448', kty='OKP', crv='X448'),
                JSONWebKey.generate(alg='ECDH-ES', kid='test-jwe-ecdh-es-direct-x25519', kty='OKP', crv='X25519'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-x448', kty='OKP', crv='X448'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-x448', kty='OKP', crv='X448'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-x448', kty='OKP', crv='X448'),
                JSONWebKey.generate(alg='ECDH-ES+A128KW', kid='test-jwe-ecdh-es-a128-kw-x25519', kty='OKP', crv='X25519'),
                JSONWebKey.generate(alg='ECDH-ES+A192KW', kid='test-jwe-ecdh-es-a192-kw-x25519', kty='OKP', crv='X25519'),
                JSONWebKey.generate(alg='ECDH-ES+A256KW', kid='test-jwe-ecdh-es-a256-kw-x25519', kty='OKP', crv='X25519'),
            ]
        )
    else:
        raise NotImplementedError
    return jwks