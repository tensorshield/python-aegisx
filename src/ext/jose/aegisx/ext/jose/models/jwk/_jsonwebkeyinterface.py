from typing import get_args
from typing import Any

import pydantic
from libcanonical.types import AwaitableBool
from libcanonical.types import AwaitableBytes

from aegisx.ext.jose.types import JSONWebAlgorithm


class JSONWebKeyInterface(pydantic.BaseModel):
    """Wrapper class to integrate :class:`JSONWebKey` and :class:`JSONWebKeySet`
    with external systems.
    """
    model_config = {'extra': 'forbid'}

    ext: bool = True


    @property
    def public(self):
        return self.get_public_key()

    @classmethod
    def supports_algorithm(cls, alg: str):
        a, _ = get_args(cls.model_fields['alg'].annotation)
        return alg in set(get_args(a))

    def get_public_key(self) -> Any:
        raise NotImplementedError

    def is_asymmetric(self) -> bool:
        raise NotImplementedError

    def sign(self, message: bytes, alg: JSONWebAlgorithm | None = None) -> AwaitableBytes:
        raise NotImplementedError

    def verify(self, signature: bytes, message: bytes, alg: Any) -> AwaitableBool:
        raise NotImplementedError