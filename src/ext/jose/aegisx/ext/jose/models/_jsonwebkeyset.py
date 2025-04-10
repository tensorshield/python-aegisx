import itertools
import pathlib
import time
from typing import Any
from typing import ClassVar
from typing import Iterable
from typing import Literal

import pydantic

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import ThumbprintHashAlgorithm
from ._jsonwebkey import JSONWebKey
from ._signature import Signature
from ._jsonwebsignature import JSONWebSignature


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
    def index(self):
        return dict(self._index)

    @property
    def public(self):
        """Return a :class:`JSONWebKeySet` containing the public keys
        in this instance.
        """
        from ._jsonpublicwebkeyset import JSONPublicWebKeySet
        return JSONPublicWebKeySet(
            keys=[x.public for x in self.keys if x.public]
        )

    @classmethod
    def fromfile(cls, fn: pathlib.Path | str):
        with open(fn, 'r') as f:
            return cls.model_validate_json(f.read())

    @classmethod
    def generate(cls, algorithms: Iterable[JSONWebAlgorithm | str]):
        keys: list[JSONWebKey] = []
        now = int(time.time())
        for alg in algorithms:
            if not isinstance(alg, JSONWebAlgorithm):
                alg = JSONWebAlgorithm.validate(alg)
            keys.append(JSONWebKey.generate(alg=alg))
            keys[-1].root.iat = now
        return JSONWebKeySet(keys=keys)

    def add(self, jwk: JSONWebKey):
        t = jwk.thumbprint(self.__thumbprint_algorithm__)
        if t not in self._index:
            self._index[t] = jwk
            if jwk.kid is not None:
                self._index[jwk.kid] = jwk
            self.keys.append(jwk)

    def clone(self):
        """Return a new :class:`JSONWebKeySet` with the same keys."""
        return JSONWebKeySet(keys=self.keys)

    def filter(
        self,
        use: Literal['sig', 'enc'],
        kid: str | None = None,
        algorithms: set[JSONWebAlgorithm] | None = None,
        thumbprints: set[str] | None = None
    ):
        """Return a new :class:`JSONWebKeySet` according to the specified
        parameters.
        """
        keys = list(self.keys)
        if kid:
            # Return immediately because if a specific kid does not match,
            # then other criteria will yield no results.
            keys = filter(lambda x: x.kid == kid, keys)
            return set(keys)

        if algorithms:
            keys = filter(lambda x: x.alg in algorithms, keys)
        if thumbprints:
            keys = filter(lambda x: x.thumbprint('sha256') in thumbprints, keys)
        return set(keys)

    def get(self, kid: str):
        return self._index.get(kid)

    def model_post_init(self, _: Any) -> None:
        for jwk in self.keys:
            self._index[jwk.thumbprint(self.__thumbprint_algorithm__)] = jwk
            if jwk.kid:
                self._index[jwk.kid] = jwk

    def algorithms(self, use: Literal['sig', 'enc']) -> set[str]:
        """Return a set indicating the supported algorithms by this
        :class:`JSONWebKeySet`.
        """
        return {
            x.alg for x in self.keys
            if x.alg is not None and x.use == use
        }

    def select(
        self,
        alg: JSONWebAlgorithm,
        kid: str | None = None,
        jwk: JSONWebKey | None = None
    ):
        candidates: list[JSONWebKey] = []
        for key in self.keys:
            if key.kid != kid:
                continue
            if kid is not None and key.kid == kid:
                candidates.append(key)
                break
            if key.alg == alg:
                candidates.append(key)
                break
        if not candidates:
            raise LookupError(
                "No key in the JSONWebKeySet could be selected."
            )
        return candidates[0]

    def thumbprints(
        self,
        using: ThumbprintHashAlgorithm = __thumbprint_algorithm__
    ):
        return {jwk.thumbprint(using) for jwk in self.keys}

    def union(self, jwks: 'JSONWebKeySet'):
        index = {**self.index, **jwks.index}
        return JSONWebKeySet(keys=list(index.values()))

    def update(self, jwks: 'JSONWebKeySet'):
        for jwk in jwks.keys:
            t = jwk.thumbprint(self.__thumbprint_algorithm__)
            if t in self._index:
                continue
            self._index[t] = jwk
            self.keys.append(jwk)

    def write(self, dst: str | pathlib.Path):
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

    async def verify(
        self,
        jws: JSONWebSignature,
        kid: str | None = None
    ) -> bool:
        """Inspect the signers of the JWS and attempt to verify at least
        one signature.
        """
        # If there are no suitable signing algorithms, bail immediately.
        verified: list[Signature] = []
        candidates = self.filter(
            use='sig',
            kid=kid,
            algorithms=jws.algorithms,
            thumbprints=jws.thumbprints
        )
        for signature, candidate in itertools.product(jws.signatures, candidates):
            if signature.is_verified():
                continue
            if not await signature.verify(candidate, jws.payload):
                continue
            verified.append(signature)
            break
        return bool(verified)

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