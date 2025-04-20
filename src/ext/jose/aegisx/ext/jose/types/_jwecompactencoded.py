from typing import Any

from libcanonical.types import StringType


class JWECompactEncoded(StringType):
    description = (
        "The JWE Compact Serialization represents encrypted content "
        "as a compact, URL-safe string.  This string is:\n\n\n```BASE64URL"
        "(UTF8(JWE Protected Header)) || '.' ||\nBASE64URL(JWE Encrypted "
        "Key) || '.' ||\nBASE64URL(JWE Initialization Vector) || '.' ||\n"
        "BASE64URL(JWE Ciphertext) || '.' ||\nBASE64URL(JWE Authentication "
        "Tag)```\n\n\nOnly one recipient is supported by the JWE Compact "
        "Serialization and it provides no syntax to represent JWE "
        "Shared Unprotected Header, JWE Per-Recipient Unprotected "
        "Header, or JWE AAD values."
    )

    @classmethod
    def validate(cls, v: str):
        if not v.count('.') == 4:
            raise ValueError("Invalid JWE Compact Encoding.")
        return cls(v)

    def compact(self): # pragma: no cover
        return self

    def dict(self) -> dict[str, Any]:
        protected, key, iv, ct, tag = str.split(self, '.')
        return {
            'protected': protected,
            'iv': iv,
            'ciphertext': ct,
            'tag': tag,
            'recipients': [{'encrypted_key': key}]
        }

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}>'