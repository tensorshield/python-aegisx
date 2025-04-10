from typing import TypeVar

import pydantic
from libcanonical.types import StringType


M = TypeVar('M', bound=pydantic.BaseModel)


class JWSCompactEncoded(StringType):

    @classmethod
    def validate(cls, v: str):
        if not v.count('.') == 2:
            raise ValueError("Invalid JWS Compact Encoding.")
        return cls(v)

    def compact(self): # pragma: no cover
        return self

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}>'