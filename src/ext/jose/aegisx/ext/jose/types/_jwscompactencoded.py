import binascii
import json
from typing import Any
from typing import ClassVar

from pydantic_core import PydanticCustomError
from libcanonical.types import StringType
from libcanonical.utils.encoding import b64decode_json
from libcanonical.utils.encoding import b64decode


class JWSCompactEncoded(StringType):
    encoding_errors: ClassVar[tuple[type[BaseException], ...]] = (
        ValueError,
        TypeError,
        binascii.Error,
        json.JSONDecodeError
    )

    @classmethod
    def validate(cls, v: str):
        if not v.count('.') == 2:
            raise ValueError("Invalid JWS Compact Encoding.")
        protected, payload, signature = str.split(v, '.')
        try:
            b64decode_json(protected)
        except cls.encoding_errors:
            raise PydanticCustomError(
                'jose.malformed.header',
                "The JWS Protected Header is malformed."
            )
        try:
            b64decode(payload)
        except cls.encoding_errors:
            raise PydanticCustomError(
                'jose.malformed.payload',
                "The JWS payload is malformed."
            )
        try:
            b64decode(signature)
        except cls.encoding_errors:
            raise PydanticCustomError(
                'jose.malformed.signature',
                "The JWS signature is malformed."
            )
        return cls(v)

    def compact(self): # pragma: no cover
        return self

    def dict(self) -> dict[str, Any]:
        protected, payload, signature = str.split(self, '.')
        if not all([protected, signature]):
            raise PydanticCustomError(
                'jose.malformed',
                'The protected header and the signature MUST be present.'
            )
        return {
            'protected': protected,
            'payload': payload,
            'signature': signature,
        }

    def with_payload(self, payload: str):
        protected, _, signature = str.split(self, '.')
        return JWSCompactEncoded(f'{protected}.{payload}.{signature}')

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}>'