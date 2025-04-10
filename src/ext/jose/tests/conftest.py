import base64
import datetime
import os
import tempfile

import pytest
from cryptography import x509
from cryptography.x509.extensions import AuthorityKeyIdentifier
from cryptography.x509.extensions import CertificatePolicies
from cryptography.x509.extensions import PolicyInformation
from cryptography.x509.extensions import SubjectKeyIdentifier
from cryptography.x509 import Name, Certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JSONWebKeySet


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
def sr25519_signing_key() -> JSONWebKey:
    k = JSONWebKey.generate(alg='EdDSA', crv='Sr25519').root # type: ignore
    assert k.kid
    return k # type: ignore


@pytest.fixture(scope='session')
def sig():
    return JSONWebKey.generate(alg='ES256')


@pytest.fixture(scope='session')
def sig_evil():
    return JSONWebKey.generate(alg='ES256')


@pytest.fixture(scope='session')
def sig_sym():
    return JSONWebKey.generate(alg='HS256')


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
        jwks.write(TEST_JWKS_PATH)
    else:
        jwks = JSONWebKeySet.fromfile(TEST_JWKS_PATH)
    return jwks




def _create_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _create_cert(
    subject: Name,
    issuer: Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    is_ca: bool = False,
    is_leaf: bool = False,
    allow_signing: bool = True,
    allow_cert_sign: bool = False,
) -> Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False
    )

    builder = builder.add_extension(
        SubjectKeyIdentifier.from_public_key(public_key),
        critical=False
    )

    builder.add_extension(
        CertificatePolicies([PolicyInformation(x509.ObjectIdentifier('2.5.29.32.0'), None)]),
        critical=False
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=allow_signing,
            key_cert_sign=allow_cert_sign,
            key_encipherment=False,
            data_encipherment=False,
            content_commitment=False,
            crl_sign=allow_cert_sign,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    if not is_leaf:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                usages=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]
            ),
            critical=False
        )

    if is_leaf:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


@pytest.fixture(scope='session')
def x5c_root() -> tuple[Certificate, ec.EllipticCurvePrivateKey]:
    root_key = _create_ec_key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    root_cert = _create_cert(
        subject=root_name,
        issuer=root_name,
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True,
        allow_cert_sign=True,
    )
    return root_cert, root_key


@pytest.fixture(scope='session')
def x5c_root_crt(x5c_root: tuple[Certificate, ec.EllipticCurvePublicKey]):
    return x5c_root[0]


@pytest.fixture(scope='session')
def x5c_no_digital_signature() -> tuple[Certificate, list[str]]:
    # Root CA
    root_key = _create_ec_key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = _create_cert(
        subject=root_name,
        issuer=root_name,
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True,
        allow_cert_sign=True,
    )

    # Intermediate CA
    intermediate_key = _create_ec_key()
    intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    intermediate_cert = _create_cert(
        subject=intermediate_name,
        issuer=root_cert.subject,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        is_ca=True,
        allow_cert_sign=True,
    )

    # Leaf cert without digital_signature
    leaf_key = _create_ec_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf NoSig")])
    leaf_cert = _create_cert(
        subject=leaf_name,
        issuer=intermediate_cert.subject,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        is_ca=False,
        is_leaf=True,
        allow_signing=False,  # <-- no digital signature
    )

    chain = [leaf_cert, intermediate_cert]
    b64_chain = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in chain
    ]

    return root_cert, b64_chain


@pytest.fixture(scope='session')
def x5c_invalid_ca() -> tuple[Certificate, list[str]]:
    # Root CA
    root_key = _create_ec_key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = _create_cert(
        subject=root_name,
        issuer=root_name,
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True,
        allow_cert_sign=True,
    )

    # Intermediate CA without cert-sign permission
    intermediate_key = _create_ec_key()
    intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bad Intermediate")])
    intermediate_cert = _create_cert(
        subject=intermediate_name,
        issuer=root_cert.subject,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        is_ca=True,
        allow_cert_sign=False,  # <-- CA flag but can't sign certs
    )

    # Leaf cert (valid, signed by invalid CA)
    leaf_key = _create_ec_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert")])
    leaf_cert = _create_cert(
        subject=leaf_name,
        issuer=intermediate_cert.subject,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        is_ca=False,
        is_leaf=True,
    )

    chain = [leaf_cert, intermediate_cert]
    b64_chain = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in chain
    ]

    return root_cert, b64_chain


@pytest.fixture(scope='session')
def x5c_non_ca() -> tuple[Certificate, list[str]]:
    # Root CA
    root_key = _create_ec_key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = _create_cert(
        subject=root_name,
        issuer=root_name,
        issuer_key=root_key,
        public_key=root_key.public_key(),
        is_ca=True,
        allow_cert_sign=True,
    )

    # Intermediate CA that is not a CA
    intermediate_key = _create_ec_key()
    intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bad Intermediate")])
    intermediate_cert = _create_cert(
        subject=intermediate_name,
        issuer=root_cert.subject,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        is_ca=False,
        allow_cert_sign=True,  # <-- No CA flag but can sign certs
    )

    # Leaf cert (valid, signed by invalid CA)
    leaf_key = _create_ec_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert")])
    leaf_cert = _create_cert(
        subject=leaf_name,
        issuer=intermediate_cert.subject,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        is_ca=False,
        is_leaf=True,
    )

    chain = [leaf_cert, intermediate_cert]
    b64_chain = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in chain
    ]

    return root_cert, b64_chain


@pytest.fixture(scope='session')
def x5c_valid_chain(
    x5c_root: tuple[Certificate, ec.EllipticCurvePrivateKey]
) -> tuple[Certificate, JSONWebKey, list[str]]:
    root_cert, root_key = x5c_root

    # Intermediate CA
    intermediate_key = _create_ec_key()
    intermediate_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")
    ])
    intermediate_cert = _create_cert(
        subject=intermediate_name,
        issuer=root_cert.subject,
        issuer_key=root_key,
        public_key=intermediate_key.public_key(),
        allow_signing=True,
        allow_cert_sign=True,
        is_ca=True
    )

    # Leaf Certificate
    leaf_key = _create_ec_key()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert")])
    leaf_cert = _create_cert(
        subject=leaf_name,
        issuer=intermediate_cert.subject,
        issuer_key=intermediate_key,
        public_key=leaf_key.public_key(),
        is_ca=False,
        is_leaf=True
    )

    # Return base64 DER chain (excluding root)
    chain = [leaf_cert, intermediate_cert]
    b64_chain = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for cert in chain
    ]

    return root_cert, JSONWebKey(private_key=leaf_key), b64_chain