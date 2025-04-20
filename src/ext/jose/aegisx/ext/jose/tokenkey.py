from typing import cast
from typing import Any
from typing import Generic
from typing import TypeVar
from typing import Unpack

import pydantic
from libcanonical.utils.encoding import b64encode
from libcanonical.utils.encoding import b64encode_json

from .models import JSONWebKey
from .types import JWSHeaderDict
from .types import JSONWebAlgorithm


H = TypeVar('H', bound=JWSHeaderDict)


class TokenKey(pydantic.BaseModel, Generic[H]):
    key: JSONWebKey = pydantic.Field(
        default=...
    )

    protected: H = pydantic.Field(
        default_factory=dict # type: ignore
    )

    unprotected: H = pydantic.Field(
        default_factory=dict # type: ignore
    )

    @property
    def HeaderType(self) -> type[Any]:
        annotation = type(self).model_fields['protected'].annotation
        assert annotation
        return annotation

    @classmethod
    def fromkey(cls, k: JSONWebKey, **protected: Unpack[JWSHeaderDict]):
        if k.alg is not None:
            protected.setdefault('alg', str(k.alg))
        return cls.model_validate(
            obj={
                'key': k,
                'protected': protected,
                'unprotected': {}
            },
            context={'strict': False}
        )

    async def sign(self, payload: bytes, params: dict[str, Any]) -> dict[str, Any]:
        adapter: pydantic.TypeAdapter[H] = pydantic.TypeAdapter(self.HeaderType)
        self.protected.update(cast(H, params))

        alg = self.key.alg or self.protected.get('alg')
    
        assert alg
        protected = b64encode_json(adapter.dump_python(self.protected, mode='json'))
        message = bytes.join(b'.', [protected, payload])
        claims: dict[str, Any] = {
            'protected': bytes.decode(protected, 'ascii'),
            'signature': b64encode(await self.key.sign(message, JSONWebAlgorithm.validate(alg)), encoder=str)
        }
        if self.unprotected: # pragma: no cover
            claims['header'] = adapter.dump_python(self.unprotected, mode='json'),
        return claims