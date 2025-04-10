from typing import Any

from ._httpsresourcelocator import HTTPSResourceLocator


class IssuerIdentifier(HTTPSResourceLocator):
    protocols = {'https'}

    @classmethod
    def validate(cls, v: str, _: Any = None):
        # RFC 9702 Section 2: The iss parameter value is the issuer
        # identifier of the authorization server that created the
        # authorization response, as defined in [RFC8414]. Its value
        # MUST be a URL that uses the "https" scheme without any query
        # or fragment components.
        self = super().validate(v, _)
        if self.parts.query:
            raise ValueError("The issuer identifier should not contain a query component.")
        if self.parts.fragment:
            raise ValueError("The issuer identifier should not contain a fragment component.")
        return self