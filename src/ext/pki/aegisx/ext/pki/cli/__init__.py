import datetime
import ipaddress
import os
import stat
from typing import Annotated

import typer
from aegisx.core.const import AEGIS_USER_DIR
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import random_serial_number
from cryptography.x509 import BasicConstraints
from cryptography.x509 import Certificate
from cryptography.x509 import CertificateBuilder
from cryptography.x509 import DNSName
from cryptography.x509 import ExtendedKeyUsage
from cryptography.x509 import IPAddress
from cryptography.x509 import KeyUsage
from cryptography.x509 import Name
from cryptography.x509 import NameAttribute
from cryptography.x509 import NameConstraints
from cryptography.x509 import SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256

from .const import INTERMEDIATE_CA_CRTFILE
from .const import INTERMEDIATE_CA_KEYFILE
from .const import LEAF_CA_CRTFILE
from .const import LEAF_CA_KEYFILE
from .const import ROOT_CA_CRTFILE
from .const import ROOT_CA_KEYFILE
from .const import USER_KEYDIR


def setup(app: typer.Typer):
    app.add_typer(pki)



pki = typer.Typer(
    name='pki'
)


@pki.command(
    name='createca',
    help='Create a certificate authority for development use.'
)
def createroot(
    domains: Annotated[list[str], typer.Option('-d')]
):
    if not ROOT_CA_KEYFILE.exists():
        os.makedirs(AEGIS_USER_DIR, exist_ok=True)
        key = generate_private_key(curve=SECP256R1())
        subject = issuer = Name([
            NameAttribute(NameOID.ORGANIZATION_NAME, "Development"),
            NameAttribute(NameOID.COMMON_NAME, "AegisX Local Development CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)\
            .replace(hour=0, minute=0, second=0, microsecond=0)
        certificate = CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(issuer)\
            .public_key(key.public_key())\
            .serial_number(random_serial_number())\
            .not_valid_before(now)\
            .not_valid_after(now + datetime.timedelta(days=3560))\
            .add_extension(
                BasicConstraints(ca=True, path_length=None),
                critical=True
            )\
            .add_extension(
                KeyUsage(
                    digital_signature=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    content_commitment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True
            )\
            .sign(key, SHA256())

        with open(ROOT_CA_KEYFILE, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
            )
        with open(ROOT_CA_CRTFILE, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    createintermediate(domains)


def createintermediate(domains: list[str]):
    with open(ROOT_CA_KEYFILE, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(ROOT_CA_CRTFILE, "rb") as f:
        root_cert = load_pem_x509_certificate(f.read())

    key = generate_private_key(SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)\
        .replace(hour=0, minute=0, second=0, microsecond=0)
    subject = Name([
        NameAttribute(NameOID.ORGANIZATION_NAME, "Development"),
        NameAttribute(NameOID.COMMON_NAME, "AegisX Intermediate CA"),
    ])
    constraints = NameConstraints(
        permitted_subtrees=[
            # Reserved and Localhost Domains
            *[DNSName(x) for x in domains],
            IPAddress(ipaddress.IPv4Network("127.0.0.1/32")),
        ],
        excluded_subtrees=None
    )

    certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                content_commitment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .add_extension(constraints, critical=True)
        .sign(private_key=root_key, algorithm=SHA256()) # type: ignore
    )
    with open(INTERMEDIATE_CA_KEYFILE, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )
    with open(INTERMEDIATE_CA_CRTFILE, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    createleaf(key, certificate, domains, now)


def createleaf(
    intermediate_key: EllipticCurvePrivateKey,
    intermediate_crt: Certificate,
    domains: list[str],
    now: datetime.datetime
):
    key = generate_rsa_private_key(
        public_exponent=65537,
        key_size=2048
    )
    subject = Name([
        NameAttribute(NameOID.COMMON_NAME, u"AegisX Development Certificate"),
    ])
    certificate = CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(intermediate_crt.subject)\
        .public_key(key.public_key())\
        .serial_number(random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=3650))\
        .add_extension(
            SubjectAlternativeName([
                DNSName(x) for x in domains
            ]),
            critical=False
        )\
        .add_extension(
            KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                key_encipherment=True,
                data_encipherment=False,
                content_commitment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )\
        .add_extension(
            ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True
        )\
        .sign(intermediate_key, SHA256())

    with open(LEAF_CA_KEYFILE, 'wb') as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )

    with open(LEAF_CA_CRTFILE, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
        f.write(intermediate_crt.public_bytes(serialization.Encoding.PEM))


@pki.command(
    name='keygen',
    help='Create an asymmetric keypair for use with AegisX.'
)
def keygen(
    name: Annotated[str, typer.Argument(help="Name of the private key.")] = 'default'
):
    if not os.path.exists(USER_KEYDIR):
        os.makedirs(USER_KEYDIR)
    path = USER_KEYDIR.joinpath(name)
    if os.path.exists(path):
        typer.secho(f'Key {name} already exists.', fg=typer.colors.RED, err=True)
        raise SystemExit(1)
    private = generate_private_key(SECP256R1())
    public = private.public_key()
    with open(USER_KEYDIR.joinpath(f'{name}.pub'), 'wb') as f:
        f.write(
            public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    with open(path, 'wb') as f:
        f.write(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )
    os.chmod(path, stat.S_IRUSR)
    typer.secho(f'Generated new P-256 private key "{name}"', fg=typer.colors.GREEN)