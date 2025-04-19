import functools
from typing import Any

import pydantic
from libcanonical.types import Base64

from .jwk import JSONWebKey
from ._jwsheader import JWSHeader


class Signature(pydantic.BaseModel):

    protected: JWSHeader = pydantic.Field(
        default_factory=JWSHeader
    )

    header: JWSHeader = pydantic.Field(
        default_factory=JWSHeader
    )

    signature: Base64 = pydantic.Field(
        default=...
    )

    @property
    def alg(self):
        assert self.protected
        assert self.protected.alg
        return self.protected.alg

    @property
    def cty(self):
        if self.protected:
            return self.protected.cty

    @property
    def key_identifier(self):
        return self.protected.key

    @property
    def typ(self):
        if self.protected:
            return self.protected.typ

    @pydantic.field_validator('header', mode='before')
    @classmethod
    def validate_header(cls, value: dict[str, Any] | None):
        if value is not None:
            if 'crit' in value:
                raise ValueError(
                    "The `crit` claim must not be in the unprotected "
                    "JWS header."
                )
        return value

    @pydantic.model_validator(mode='after')
    def validate_header_presence(self):
        if all([self.protected.is_empty(), self.header.is_empty()]):
            raise ValueError(
                'At least one of the "protected" and "header" '
                'members MUST be present'
            )
        if (self.protected.model_fields_set & self.header.model_fields_set):
            raise ValueError(
                'The Header Parameter values in the JWS Protected Header and '
                'JWS Unprotected Header MUST be disjoint.'
            )
        return self

    @functools.cached_property
    def _header(self):
        assert isinstance(self.protected, Base64)
        return JWSHeader.model_validate_json(self.protected)

    def get_signing_input(self, payload: bytes):
        assert self.protected.encoded
        return b'.'.join([self.protected.encoded, payload])

    def verify(self, key: JSONWebKey, payload: bytes):
        alg = self.protected.alg or self.header.alg
        if alg is None:
            raise ValueError('The "alg" JWS Header Claim is required.')
        return  key.verify(self.signature, payload, alg)

    def __bytes__(self):
        return bytes(self.signature)