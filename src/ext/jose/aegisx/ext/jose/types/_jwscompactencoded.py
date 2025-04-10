from typing import Any

from libcanonical.types import StringType


class JWSCompactEncoded(StringType):

    @classmethod
    def validate(cls, v: str):
        if not v.count('.') == 2:
            raise ValueError("Invalid JWS Compact Encoding.")
        return cls(v)

    def compact(self): # pragma: no cover
        return self

    def dict(self) -> dict[str, Any]:
        protected, payload, signature = str.split(self, '.')
        return {
            'protected': protected,
            'payload': payload,
            'signature': signature,
        }

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}>'