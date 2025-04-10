import json
from typing import Any
from typing import ClassVar

import pydantic
from libcanonical.utils.encoding import b64encode
from libcanonical.types import Base64

from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkey import JSONWebKey


class JWEHeader(pydantic.BaseModel):
    forbidden_critical_claims: ClassVar[set[str]] = {
        'alg', 'enc', 'zip', 'jku', 'jwk',
        'kid', 'x5u', 'x5t', 'x5t', 'x5t#S256',
        'typ', 'cty', 'crit', 'epk', 'apu', 'apv',
        'iv', 'tag', 'p2s', 'p2c'
    }

    alg: JSONWebAlgorithm | None = pydantic.Field(
        default=None
    )

    enc: JSONWebAlgorithm | None = pydantic.Field(
        default=None
    )

    kid: str | None = pydantic.Field(
        default=None
    )

    jwk: JSONWebKey | None = pydantic.Field(
        default=None
    )

    cty: str | None = pydantic.Field(
        default=None
    )

    typ: str | None = pydantic.Field(
        default=None
    )

    crit: list[str] | None = pydantic.Field(
        default=None,
        min_length=1,
    )

    iv: Base64 = pydantic.Field(
        default_factory=Base64
    )

    tag: Base64 = pydantic.Field(
        default_factory=Base64
    )

    epk: JSONWebKey | None = pydantic.Field(
        default=None,
        title="Ephemeral Public Key (EPK)",
        description=(
            "The `epk` (ephemeral public key) value created by the originator "
            "for the use in key agreement algorithms.  This key is represented "
            "as a JSON Web Key [JWK] public key value.  It MUST contain only "
            "public key parameters and SHOULD contain only the minimum JWK "
            "parameters necessary to represent the key; other JWK parameters "
            "included can be checked for consistency and honored, or they can "
            "be ignored. This Header Parameter MUST be present."
        )
    )

    apu: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Agreement PartyUInfo",
        description=(
            "The `apu` (agreement PartyUInfo) value for key agreement algorithms "
            "using it (such as `ECDH-ES`), represented as a base64url-encoded "
            "string. When used, the PartyUInfo value contains information about "
            "the producer.  Use of this Header Parameter is OPTIONAL."
        )
    )

    apv: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Agreement PartyVInfo",
        description=(
            "The `apv` (agreement PartyVInfo) value for key agreement algorithms "
            "using it (such as `ECDH-ES`), represented as a base64url encoded "
            "string. When used, the PartyVInfo value contains information about "
            "the recipient.  Use of this Header Parameter is OPTIONAL."
        )
    )

    # Claims from encrypted JWT.
    iss: str | None = pydantic.Field(
        default_factory=lambda: None,
        title="Issuer",
        description=(
            "The `iss` (issuer) claim identifies the principal that issued the "
            "JWT.  The processing of this claim is generally application specific. "
            "The `iss` value is a case-sensitive string containing a StringOrURI "
            "value.  Use of this claim is OPTIONAL."
        )
    )

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
            forbidden_claims = set(cls.forbidden_critical_claims)
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

    def keys(self):
        return set(self.model_dump(exclude_defaults=True))

    def urlencode(self):
        claims = self.model_dump(
            exclude_defaults=True,
            exclude_none=True,
            mode='json'
        )

        # Compute the Encoded Protected Header value BASE64URL(UTF8(JWE Protected Header)).
        # If the JWE Protected Header is not present (which can only happen when using
        # the JWE JSON Serialization and no "protected" member is present), let this value
        # be the empty string.
        match bool(claims):
            case False: return b''
            case True: return b64encode(json.dumps(claims), encoder=bytes)

    def __bytes__(self):
        claims = self.model_dump(
            exclude_defaults=True,
            exclude_none=True,
            mode='json'
        )
        match bool(claims):
            case True: return str.encode(json.dumps(claims), 'utf-8')
            case False: return b''

    def __or__(self, other: Any):
        if not isinstance(other, JWEHeader):
            return NotImplemented
        return JWEHeader.model_validate({
            **self.model_dump(exclude_defaults=True, exclude_none=True),
            **other.model_dump(exclude_defaults=True, exclude_none=True),
        })

    def __bool__(self):
        return bool(self.model_dump(exclude_defaults=True))