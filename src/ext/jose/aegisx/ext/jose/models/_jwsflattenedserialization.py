from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic
from libcanonical.types import Base64

from ._jwsheader import JWSHeader
from ._jwsvalidationbase import JWSValidationBase
from ._jsonwebtoken import JSONWebToken
from ._signature import Signature


T = TypeVar('T', default=bytes, bound=bytes | JSONWebToken)


class JWSFlattenedSerialization(JWSValidationBase, Generic[T]):
    model_config = {
        'extra': 'forbid',
        'populate_by_name': True
    }

    protected: JWSHeader = pydantic.Field(
        default_factory=JWSHeader
    )

    signature: Base64 = pydantic.Field(
        default=...
    )

    unprotected: JWSHeader = pydantic.Field(
        default_factory=JWSHeader,
        alias='header'
    )

    payload: bytes = pydantic.Field(
        default=...
    )

    @property
    def message(self):
        return b'.'.join([self.protected.encoded, self.payload])

    @pydantic.field_validator('protected', mode='before')
    def preprocess_headers(cls, value: str | None | Any, info: pydantic.ValidationInfo):
        if value is not None and not isinstance(value, str):
            raise ValueError(
                'The JWS Protected Header must be a bas64-urlencoded '
                'string.'
            )
        return JWSHeader.model_validate(value, context=info.context)

    @pydantic.model_validator(mode='after')
    def validate_header(self):
        p = self.protected.model_fields_set
        u = self.unprotected.model_fields_set
        if not bool(p | u):
            raise ValueError(
                'one or both of the JWS Protected Header and JWS '
                'Unprotected Header MUST be present.'
            )

        if (p & u):
            raise ValueError(
                "The header parameters in the protected and unprotected "
                "header must be disjoint."
            )

        if not self.protected.alg and not self.unprotected.alg:
            raise ValueError('The "alg" Header Parameter MUST be present')
        return self

    def get_headers(self) -> tuple[JWSHeader | None, JWSHeader | None]:
        return self.protected, self.unprotected

    def get_payload(self):
        return bytes.decode(self.payload, 'ascii')

    def get_raw_payload(self) -> bytes:
        return self.payload

    def get_signatures(self) -> list[Signature]:
        return [
            Signature.model_validate({
                'protected': self.protected,
                'header': self.unprotected,
                'signature': self.signature,
            })
        ]

    def __str__(self):
        return self.model_dump_json(
            exclude_defaults=True,
            exclude_none=True,
            exclude_unset=True
        )

    def __bytes__(self):
        return str.encode(str(self), 'ascii')