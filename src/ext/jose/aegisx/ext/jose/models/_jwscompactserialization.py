from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import JWSCompactEncoded
from ._jwsheader import JWSHeader
from ._jwsvalidationbase import JWSValidationBase
from ._jsonwebtoken import JSONWebToken
from ._signature import Signature


T = TypeVar('T', default=bytes, bound=bytes | JSONWebToken)


class JWSCompactSerialization(JWSValidationBase, Generic[T]):
    model_config = {'extra': 'forbid'}

    protected: JWSHeader = pydantic.Field(
        default=...
    )

    signature: Base64 = pydantic.Field(
        default=...
    )

    payload: bytes = pydantic.Field(
        default=...
    )

    @pydantic.field_validator('protected', mode='before')
    def preprocess_protected(cls, value: str | None, info: pydantic.ValidationInfo):
        if not isinstance(value, str):
            raise ValueError(
                'The JWS Protected Header must be a bas64-urlencoded '
                'string.'
            )
        return JWSHeader.model_validate(value, context=info.context)

    @pydantic.model_validator(mode='wrap')
    @classmethod
    def preprocess(
        cls,
        value: Any,
        nxt: pydantic.ValidatorFunctionWrapHandler
    ):
        if isinstance(value, str):
            value = JWSCompactEncoded.validate(value)
        if isinstance(value, JWSCompactEncoded):
            value = value.dict()
        return nxt(value)

    @pydantic.model_validator(mode='after')
    def postprocess_protected(self):
        if not self.protected.alg:
            raise ValueError('The "alg" Header Parameter MUST be present')
        return self

    def get_headers(self) -> tuple[JWSHeader | None, JWSHeader | None]:
        return self.protected, None

    def get_raw_payload(self) -> bytes:
        return self.payload

    def get_payload(self):
        return bytes.decode(self.payload, 'ascii')

    def get_signatures(self) -> list[Signature]:
        return [
            Signature(
                protected=self.protected,
                signature=self.signature,
            )
        ]