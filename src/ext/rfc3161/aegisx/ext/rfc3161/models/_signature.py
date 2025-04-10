import datetime
from typing import Any
from typing import ClassVar
from typing import Literal

import pydantic
from pyasn1.codec.der.decoder import decode
from pyasn1_modules.rfc2315 import SignerInfo

from aegisx.ext.rfc3161.utils import digest_algorithm_name
from ._issuer import Issuer


class Signer(pydantic.BaseModel):
    model_oid_fields: ClassVar[dict[str, str]] = {
        '1.2.840.113549.1.9.5': 'signing_time',
    }

    serial: int = pydantic.Field(
        default=...
    )

    issuer: Issuer = pydantic.Field(
        default=...
    )

    dig: Literal['sha1', 'sha256', 'sha384', 'sha512'] = pydantic.Field(
        default=...
    )

    signed: datetime.datetime | None = pydantic.Field(
        default=None,
        title="Issued at",
        description=(
            "The date/time at which the TSA created the "
            "signature."
        )
    )

    @pydantic.model_validator(mode='before')
    @classmethod
    def preprocess(cls, value: Any | SignerInfo):
        if isinstance(value, SignerInfo):
            params: dict[str, Any] = {
                'serial': int(value['issuerAndSerialNumber']['serialNumber']), # type: ignore
                'issuer': Issuer.model_validate(value['issuerAndSerialNumber']['issuer']),
                'dig': digest_algorithm_name(str(value['digestAlgorithm']['algorithm'])) # type: ignore
            }
            for attribute in value['authenticatedAttributes']: # type: ignore
                oid: str = str(attribute['type']) # type: ignore
                match oid: # type: ignore
                    case '1.2.840.113549.1.9.16.2.47':
                        if len(attribute['values']) != 1: # type: ignore
                            raise ValueError(
                                "Unexpected length for 1.2.840.113549.1.9.16.2.47:"
                                f"{len(attribute['values'])}" # type: ignore
                            )
                        # For now we do nothing with this datastructure.
                    case '1.2.840.113549.1.9.3':
                        # Content Type
                        pass
                    case '1.2.840.113549.1.9.5':
                        # Signing time (Defined in RFC 5652, and originally in PKCS#9)
                        decoded, _ = decode(attribute['values'][0]) # type: ignore
                        params['signed'] = datetime.datetime.strptime(
                            str(decoded), # type: ignore
                            '%Y%m%d%H%M%SZ',
                        ).replace(tzinfo=datetime.timezone.utc)
                    case '1.2.840.113549.1.9.4':
                        # message digest
                        pass
                    case '1.2.840.113549.1.9.52':
                        # RFC 6211 Cryptographic Message Syntax (CMS)
                        # algorithm protection.
                        pass
                    case '1.2.840.113549.1.9.16.2.12':
                        # An identifier of an attribute found in signed-attribute
                        # collections of a Cryptographic Message Syntax "Signed
                        # Data" object. The attribute value is a SigningCertificate
                        # sequence, defined in RFC 2634, "Enhanced Security Services
                        # for S/MIME". The attribute allows a message signer provide
                        # a signed version of the certificate identifier to be used
                        # for signature verification. This thwarts some certificate
                        # substitution attacks.
                        pass
                    case '1.2.840.113549.1.9.16.2.15':
                        # sigpolicy
                        pass
                    case _:
                        raise ValueError(f'Unknown OID: {oid}')
            value = params
        return value