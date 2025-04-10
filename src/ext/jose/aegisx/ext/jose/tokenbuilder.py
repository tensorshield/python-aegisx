from typing import cast
from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic
from libcanonical.types import HTTPResourceLocator

from .models import JSONWebKey
from .models import JSONWebSignature
from .models import JSONWebToken


T = TypeVar('T', bound=JSONWebToken | JSONWebSignature)


class TokenBuilder(Generic[T]):
    adapter: pydantic.TypeAdapter[T]
    managed_claims: set[str] = set()

    _audience: set[HTTPResourceLocator]
    _issuer: HTTPResourceLocator | None
    _claims: dict[str, Any]
    _signers: list[JSONWebKey]

    def __init__(
        self,
        types: type[T]
    ):
        self.adapter = pydantic.TypeAdapter(types)
        self._audience = set()
        self._claims = {}
        self._issuer = None
        self._signers = []

    def audience(self, audience: set[str] | str):
        if isinstance(audience, str):
            audience = {audience}
        self._audience.update(map(HTTPResourceLocator.validate, audience))
        return self

    def issuer(self, iss: HTTPResourceLocator | str):
        if not isinstance(iss, HTTPResourceLocator):
            iss = HTTPResourceLocator.validate(iss)
        self._issuer = iss
        return self

    def update(self, **claims: Any):
        self._claims.update(claims)
        return self

    def sign(self, key: JSONWebKey) -> 'TokenBuilder[JSONWebSignature]':
        self._signers.append(key)
        return cast(TokenBuilder[JSONWebSignature], self)

    async def build(self) -> T:
        artifact = self.adapter.validate_python(self._claims)

        assert isinstance(artifact, JSONWebToken)
        if self._audience:
            artifact.aud = self._audience
        if self._issuer:
            artifact.iss = self._issuer
        if self._signers:
            artifact = JSONWebSignature.fromjwt(artifact)
            for signer in self._signers:
                artifact.sign(signer)
            await artifact.finalize()
        return artifact # type: ignore