from typing import Any

from libcanonical.types import HTTPResourceLocator


class JSONWebKeySetURL(HTTPResourceLocator):
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