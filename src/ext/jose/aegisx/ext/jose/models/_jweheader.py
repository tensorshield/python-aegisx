from typing import Any
from typing import ClassVar

import pydantic
from libcanonical.types import Base64
from libcanonical.types import Base64URLEncoded
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64decode_json

from aegisx.ext.jose.types import JSONWebAlgorithm
from .jwk import JSONWebKey
from ._joseheader import JOSEHeader


class JWEHeader(JOSEHeader):
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

    x5t: Base64URLEncoded | None = pydantic.Field(
        default=None
    )

    x5t_s256: Base64URLEncoded | None = pydantic.Field(
        default=None,
        alias='x5t#S256'
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
    )

    aud: set[HTTPResourceLocator | str] = pydantic.Field(
        default_factory=set
    )

    sub: str | None = pydantic.Field(
        default_factory=lambda: None,
    )

    encoded: bytes = pydantic.Field(
        default_factory=bytes,
        frozen=True,
        exclude=True
    )

    @pydantic.model_validator(mode='before')
    def preprocess(cls, value: Any):
        if isinstance(value, str):
            value = {**b64decode_json(value), 'encoded': value.encode('ascii')} # type: ignore
        return value

    def __or__(self, other: Any):
        if not isinstance(other, JWEHeader):
            return NotImplemented
        return JWEHeader.model_validate({
            **self.model_dump(exclude_defaults=True, exclude_unset=True, exclude_none=True),
            **other.model_dump(exclude_defaults=True, exclude_unset=True, exclude_none=True),
        })
