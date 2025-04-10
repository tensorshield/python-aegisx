import base64
import pytest
import datetime

from cryptography import x509
from cryptography.x509 import Name, Certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


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
            critical=True
        )

    if is_leaf:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]),
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
        is_ca=True
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
def x5c_valid_chain(x5c_root: tuple[Certificate, ec.EllipticCurvePrivateKey]) -> list[str]:
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

    return b64_chain