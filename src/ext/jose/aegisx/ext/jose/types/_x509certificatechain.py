import base64
import hashlib
from typing import Any
from typing import Iterable

from cryptography.x509 import load_der_x509_certificate
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.serialization import Encoding
from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


MAX_CHAIN_DEPTH = 5


class X509CertificateChain:
    description = (
        "The `x5c` (X.509 certificate chain) Header Parameter contains the "
        "X.509 public key certificate or certificate chain (RFC5280) "
        "corresponding to the key used to digitally sign the JWS. The "
        "certificate or certificate chain is represented as a JSON array "
        "of certificate value strings. Each string in the array is a base64-"
        "encoded (Section 4 of RFC4648 -- not base64url-encoded) DER (ITU."
        "X690.2008) PKIX certificate value. The certificate containing the "
        "public key corresponding to the key used to digitally sign the JWS "
        "MUST be the first certificate. This MAY be followed by additional "
        "certificates, with each subsequent certificate being the one used "
        "to certify the previous one. The recipient MUST validate the "
        "certificate chain according to RFC 5280 (RFC5280) and consider "
        "the certificate or certificate chain to be invalid if any validation "
        "failure occurs. Use of this Header Parameter is OPTIONAL."
    )

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.list_schema(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(list),
                    core_schema.no_info_plain_validator_function(cls.fromlist)
                ])
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(cls.serialize)
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        schema = handler(core_schema.list_schema())
        schema['title'] = "X.509 Certficate Chain"
        schema['description'] = cls.description
        return schema

    @classmethod
    def decode_certificate(cls, encoded: bytes | str):
        if isinstance(encoded, bytes):
            encoded = bytes.decode(encoded, 'ascii')
        return cls.load_der_certificate(base64.b64decode(encoded))

    @classmethod
    def encode_certificate(cls, certificate: Certificate) -> str:
        der = certificate.public_bytes(encoding=Encoding.DER)
        return bytes.decode(base64.b64encode(der), 'ascii')

    @classmethod
    def load_der_certificate(cls, der: bytes):
        return load_der_x509_certificate(der)

    @classmethod
    def fromlist(cls, x5c: list[str]):
        return cls(map(cls.decode_certificate, x5c))

    @property
    def thumbprint(self):
        return hashlib.sha1(self.leaf.public_bytes(encoding=Encoding.DER)).digest()

    @property
    def thumbprint_sha256(self):
        return hashlib.sha256(self.leaf.public_bytes(encoding=Encoding.DER)).digest()

    def __init__(
        self,
        chain: Iterable[Certificate]
    ):
        if not chain:
            raise ValueError("The chain contains no certificates.")
        self.chain = list(chain)
        self.leaf = self.chain[0]
        self.intermediates = self.chain[1:]

    def is_trusted(self, root: Certificate | None = None) -> bool:
        raise NotImplementedError

    def serialize(self):
        return [
            self.encode_certificate(self.leaf),
            *[self.encode_certificate(c) for c in self.intermediates]
        ]