import functools
import time
from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.jose.types import FeatureNotImplemented
from aegisx.ext.jose.types import InvalidSignature
from .models import JSONWebToken
from .models import JSONWebKeySet
from .models import JSONWebSignature
from .types import JSONWebKeySetURL
from .types import X509CertificateURL


T = TypeVar('T')


class TokenValidator(Generic[T]):
    adapter: pydantic.TypeAdapter[T]
    audience: set[HTTPResourceLocator] | None = None
    issuer: set[HTTPResourceLocator]

    @property
    def context(self) -> dict[str, Any]:
        return {
            'audiences': self.audience,
            'issuers': self.issuer,
            'mode': 'deserialize',
            'now': int(time.time()),
        }

    def __init__(
        self,
        types: type[T],
        *,
        audience: set[HTTPResourceLocator] | str | None = None,
        issuer: set[HTTPResourceLocator] | str | None = None,
        jwks: JSONWebKeySet | None = None
    ):
        if isinstance(audience, str):
            audience = {HTTPResourceLocator.validate(audience)}
        if isinstance(issuer, str):
            issuer = {HTTPResourceLocator.validate(issuer)}
        self.adapter = pydantic.TypeAdapter(types)
        self.audience = audience or set()
        self.issuer = issuer or set()
        self.jwks = jwks or JSONWebKeySet()

    def deserialize(self, payload: dict[str, Any]):
        return self.adapter.validate_python(
            payload,
            context=self.context
        )

    def is_trusted_issuer(self, iss: HTTPResourceLocator | str | None):
        return False

    def validate_payload(self, payload: T) -> T:
        return payload

    async def import_keys(self, headers: list[dict[str, Any]], payload: T):
        """Inspect the JWS Headers and the JWT ``iss`` claim for
        any trusted domains or issuers and lookup their public
        keys.
        """
        urls: set[HTTPResourceLocator] = set()
        if isinstance(payload, JSONWebToken) and self.is_trusted_issuer(payload.iss):
            assert isinstance(payload.iss, HTTPResourceLocator)
            urls.add(payload.iss)
        for header in headers:
            if header.get('jku'):
                assert isinstance(header['jku'], JSONWebKeySetURL)
                urls.add(header['jku'])
            if header.get('x5u'):
                assert isinstance(header['jku'], X509CertificateURL)
                urls.add(header['jku'])
        if not urls:
            return

        raise FeatureNotImplemented(
            "Loading key material from external sources using the \"jku\" "
            "or \"x5u\" claims is not implemented."
        )

    async def verify(self, jws: JSONWebSignature):
        """Verify the signature of a JSON Web Signature (JWS) and return
        a boolean indicating if at least one of the signatures is valid.
        """
        return await self.jwks.verify(jws)

    @functools.singledispatchmethod
    async def validate(self, token: Any) -> T:
        raise NotImplementedError(repr(token))

    @validate.register
    async def _(self, token: JSONWebSignature) -> T:
        payload = self.deserialize(token.loads())
        if not await self.verify(token):
            raise InvalidSignature
        return await self.validate(payload)

    @validate.register
    async def _(self, token: dict) -> T: # type: ignore
        return await self.validate(
            self.adapter.validate_python(
                token,
                context=self.context
            )
        )

    @validate.register
    async def _(self, token: JSONWebToken) -> T:
        return self.validate_payload(token) # type: ignore