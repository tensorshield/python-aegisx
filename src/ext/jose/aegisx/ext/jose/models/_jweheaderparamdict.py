from typing import Literal
from typing import NotRequired
from typing import TypedDict

from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkey import JSONWebKey


class JWEHeaderParamDict(TypedDict):
    alg: JSONWebAlgorithm
    enc: JSONWebAlgorithm
    zip: NotRequired[Literal['DEF']]
    jku: NotRequired[str]
    jwk: NotRequired[JSONWebKey]
    kid: NotRequired[str]
    x5u: NotRequired[str]
    x5c: NotRequired[list[str]]
    x5t: NotRequired[str]
    x5t_s256: NotRequired[str]