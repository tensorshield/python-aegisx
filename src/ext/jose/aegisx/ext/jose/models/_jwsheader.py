import functools
from typing import Any
from typing import ClassVar

import pydantic
from libcanonical.types import Base64URLEncoded

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JSONWebKeySetURL
from aegisx.ext.jose.types import X509CertificateURL
from aegisx.ext.jose.types import X509CertificateChain
from .jwk import JSONWebKey
from ._joseheader import JOSEHeader
from ._keyidentifier import KeyIdentifier


class JWSHeader(JOSEHeader):
    key_identifier_claims: ClassVar[set[str]] = {
        "jku", "jwk", "kid",
        "x5u", "x5c", "x5t",
        "alg"
    }

    model_config = {
        'populate_by_name': True
    }

    alg: JSONWebAlgorithm | None = pydantic.Field(
        default=None
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

    x5c: X509CertificateChain | None = pydantic.Field(
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

    encoded: bytes = pydantic.Field(
        default=b'',
        exclude=True
    )

    @functools.cached_property
    def key(self):
        return KeyIdentifier.model_validate(self.model_dump())

    @functools.cached_property
    def key_identifiers(self) -> set[str]:
        return set(self.model_fields_set) & self.key_identifier_claims

    def is_empty(self):
        return not self.model_fields_set

    def __str__(self):
        return self.model_dump_json(
            exclude_none=True,
            by_alias=True
        )

    def __or__(self, other: Any):
        if not isinstance(other, JWSHeader):
            return NotImplemented
        return JWSHeader.model_validate({
            **self.model_dump(exclude_defaults=True, exclude_unset=True, exclude_none=True),
            **other.model_dump(exclude_defaults=True, exclude_unset=True, exclude_none=True),
        })
