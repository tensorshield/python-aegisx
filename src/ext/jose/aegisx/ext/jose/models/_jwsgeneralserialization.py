from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic

from aegisx.ext.jose.types import JWSCompactEncoded
from ._jsonwebtoken import JSONWebToken
from ._jwsheader import JWSHeader
from ._jwsvalidationbase import JWSValidationBase
from ._signature import Signature


T = TypeVar('T', default=bytes, bound=bytes | JSONWebToken)


class JWSGeneralSerialization(JWSValidationBase, Generic[T]):
    model_config = {
        'extra': 'forbid',
        'populate_by_name': True
    }

    payload: bytes = pydantic.Field(
        default=...
    )

    signatures: list[Signature] = pydantic.Field(
        default=...,
        min_length=1
    )

    @property
    def headers(self) -> tuple[None, None, list[JWSHeader]]:
        return None, None, [
            signature.header | signature.protected
            for signature in self.signatures
        ]

    @pydantic.model_validator(mode='before')
    def preprocess(cls, value: Any):
        if isinstance(value, str):
            value = JWSCompactEncoded.validate(value)
        if isinstance(value, JWSCompactEncoded):
            value = value.dict()
            value['signatures'] = [
                {
                    'protected': value.pop('protected', None),
                    'signature': value.pop('signature', None)
                }
            ]
        return value

    def get_payload(self):
        return bytes.decode(self.payload, 'ascii')

    def get_raw_payload(self) -> bytes:
        return self.payload

    def get_signatures(self) -> list[Signature]:
        return self.signatures