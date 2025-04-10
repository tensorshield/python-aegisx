from typing import SupportsBytes

import pydantic
from libcanonical.types import Base64
from libcanonical.types import Base64URLEncoded
from libcanonical.utils.encoding import b64decode_json
from libcanonical.utils.encoding import b64encode

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JSONWebKeySetURL
from aegisx.ext.jose.types import X509CertificateURL
from ._jsonwebkey import JSONWebKey


class JWSHeader(pydantic.BaseModel):
    model_config = {'extra': 'forbid'}

    alg: JSONWebAlgorithm = pydantic.Field(
        default=...
    )

    jku: JSONWebKeySetURL | None = pydantic.Field(
        default=None
    )

    jwk: JSONWebKey | None = pydantic.Field(
        default=None
    )

    kid: str | None = pydantic.Field(
        default=None
    )

    x5u: X509CertificateURL | None = pydantic.Field(
        default=None
    )

    x5c: list[Base64] | None = pydantic.Field(
        default=None
    )

    x5t: Base64URLEncoded | None = pydantic.Field(
        default=None
    )

    x5t_s256: Base64URLEncoded | None = pydantic.Field(
        default=None,
        alias='x5t#S256'
    )

    typ: str | None = pydantic.Field(
        default=None
    )

    cty: str | None = pydantic.Field(
        default=None
    )

    crit: list[str] | None = pydantic.Field(
        default=None,
        min_length=1,
    )

    @classmethod
    def model_validate_b64(cls, buf: bytes):
        return cls.model_validate(b64decode_json(buf))

    @pydantic.field_validator('cty', 'typ', mode='before')
    def preprocess_media_type(cls, value: str | None):
        # RFC 7515: A recipient using the media type value MUST treat it as
        # if "application/" were prepended to any "typ" value not containing
        # a '/'.  For instance, a "typ" value of "example" SHOULD be used
        # to represent the "application/example" media type, whereas the
        # media type "application/example;part="1/2"" cannot be shortened
        # to "example;part="1/2"".
        if value is not None and value == 'JWT':
            value = str.lower(value)
        if value is not None and value.find('/') == -1:
            value = f'application/{value}'
        return value

    @pydantic.field_validator('crit', mode='before')
    @classmethod
    def validate_crit(cls, value: list[str] | None):
        if value is not None:
            forbidden_claims = set([
                field.alias or name
                for name, field in JWSHeader.model_fields.items()
            ])
            known_claims = set([
                field.alias or name
                for name, field in cls.model_fields.items()
            ])
            critical = set(value)
            if (critical & forbidden_claims):
                raise ValueError(f"The `crit` claim contains illegal values.")
            if (critical - known_claims):
                unknown = critical - known_claims
                raise ValueError(
                    f"Header contains critical unknown claims: {str.join(', ', unknown)}"
                )
            if len(critical) != len(value):
                raise ValueError("The `crit` claim must not contain duplicates.")
        return value

    def __str__(self):
        return self.model_dump_json(
            exclude_none=True,
            by_alias=True
        )

    def __bytes__(self):
        return Base64(str.encode(str(self), 'utf-8'))

    async def sign(self, signer: JSONWebKey, payload: bytes | SupportsBytes):
        message = bytes.join(b'.', [
            b64encode(bytes(self)),
            bytes(payload)
        ])
        return Base64(signer.sign(message, alg=self.alg))