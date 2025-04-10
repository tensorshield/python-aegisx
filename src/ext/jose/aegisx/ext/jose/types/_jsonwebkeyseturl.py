from typing import Any
from typing import ClassVar

import httpx
from libcanonical.types import HTTPResourceLocator


CACHE: dict['JSONWebKeySetURL', Any] = {}


class JSONWebKeySetURL(HTTPResourceLocator):
    __cache__: ClassVar[dict['JSONWebKeySetURL', Any]] = CACHE
    protocols = {'https'}
    description = (
        "The `jku` (JWK Set URL) Header Parameter is a URI that refers to "
        "a resource for a set of JSON-encoded public keys, one of which "
        "corresponds to the key used to digitally sign the JWS.  The keys "
        "MUST be encoded as a JWK Set.  The protocol used to acquire the "
        "resource MUST provide integrity protection; an HTTP GET request "
        "to retrieve the JWK Set MUST use Transport Layer Security (TLS) "
        "(RFC2818, RFC5246); and the identity of the server MUST be "
        "validated, as per Section 6 of RFC 6125. Also, see Section 8 on "
        "TLS requirements. Use of this Header Parameter is OPTIONAL."
    )

    @classmethod
    def validate(cls, v: str, _: Any = None):
        try:
            return super().validate(v)
        except ValueError:
            raise ValueError(
                "The \"jku\" (JWK Set URL) Header Parameter MUST "
                "use TLS."
            )

    async def get(self, timeout: int = 10):
        """Lookup the JSON Web Key Set (JWKS) and return its
        contents as a dictionary.
        """
        if self not in self.__cache__:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url=self, follow_redirects=True)
                if response.status_code != 200:
                    raise ValueError
                self.__cache__[self] = response.json()
        return self.__cache__[self]

    async def __await__(self):
        return self.get().__await__()