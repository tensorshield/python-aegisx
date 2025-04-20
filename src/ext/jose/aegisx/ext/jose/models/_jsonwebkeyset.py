import asyncio
import pathlib
from typing import Any
from typing import ClassVar
from typing import Union

import pydantic

from aegisx.ext.jose.types import NotVerifiable
from aegisx.ext.jose.types import ThumbprintHashAlgorithm
from aegisx.ext.jose.types import Undecryptable
from aegisx.ext.jose.keyselector import KeySelector
from .jwk import JSONWebKey
from ._jwegeneralserialization import JWEGeneralSerialization
from ._signature import Signature


class JSONWebKeySet(pydantic.BaseModel):
    model_config = {'extra': 'forbid'}
    __thumbprint_algorithm__: ClassVar[ThumbprintHashAlgorithm] = 'sha256'

    _index: dict[str, JSONWebKey] = pydantic.PrivateAttr(
        default_factory=dict
    )

    keys: list[JSONWebKey] = pydantic.Field(
        default_factory=list,
        frozen=True
    )

    @property
    def enc(self):
        return list(filter(lambda key: key.use in {None, 'enc'}, self.keys))

    @property
    def index(self):
        return dict(self._index)

    @property
    def sig(self):
        return list(filter(lambda key: key.use in {None, 'sig'}, self.keys))

    @classmethod
    def fromfile(cls, fn: pathlib.Path | str):
        with open(fn, 'r') as f:
            return cls.model_validate_json(f.read())

    def add(self, jwk: JSONWebKey):
        t = jwk.thumbprint(self.__thumbprint_algorithm__)
        if t not in self._index:
            self._index[t] = jwk
            if jwk.kid is not None:
                self._index[jwk.kid] = jwk
            self.keys.append(jwk)

    def get(self, kid: str):
        return self._index.get(kid)

    def model_post_init(self, _: Any) -> None:
        for jwk in self.keys: # pragma: no cover
            self._index[jwk.thumbprint(self.__thumbprint_algorithm__)] = jwk
            if jwk.kid:
                self._index[jwk.kid] = jwk

    def union(self, jwks: 'JSONWebKeySet'):
        index = {**self.index, **jwks.index}
        return JSONWebKeySet(keys=list(index.values()))

    def update(self, keys: Union['JSONWebKeySet', list[JSONWebKey]]):
        if isinstance(keys, JSONWebKeySet):
            keys = keys.keys
        for jwk in keys:
            t = jwk.thumbprint(self.__thumbprint_algorithm__)
            if t in self._index: # pragma: no cover
                continue
            self._index[t] = jwk
            self.keys.append(jwk)

    def write(self, dst: str | pathlib.Path): # pragma: no cover
        """Writes the JSON Web Key Set (JWKS) to the given
        destination.
        """
        with open(dst, 'w') as f:
            f.write(
                self.model_dump_json(
                    indent=2,
                    exclude_none=True
                )
            )

    async def decrypt(self, jwe: JWEGeneralSerialization):
        selector = KeySelector(self.enc)
        for key in selector:
            try:
                result = await jwe.decrypt(key)
            except Undecryptable:
                continue
            break
        else:
            raise Undecryptable
        return result

    async def verify(
        self,
        signature: Signature,
        message: bytes
    ) -> bool:
        if not self.sig:
            raise NotVerifiable
        assert self.sig
        candidates = signature.candidates(KeySelector(self.sig))
        if not candidates:
            raise NotVerifiable
        tasks: list[asyncio.Task[bool]] = [
            asyncio.create_task(self._verify(k, signature, message))
            for k in candidates
        ]
        return any(await asyncio.gather(*tasks))

    def __or__(self, jwks: Any):
        if not isinstance(jwks, JSONWebKeySet):
            return NotImplemented

        return self.union(jwks)

    def __len__(self):
        return len(self.keys)

    def __contains__(self, jwk: Any):
        if not isinstance(jwk, JSONWebKey):
            return NotImplemented
        return jwk.thumbprint(self.__thumbprint_algorithm__) in self._index

    async def _verify(self, key: JSONWebKey, signature: Signature, message: bytes):
        return bool(await key.verify(bytes(signature), message, alg=signature.alg))