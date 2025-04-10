from typing import Union

from ._jsonwebkey import JSONWebKey
from ._jsonwebkeyedwardscurvepublic import JSONWebKeyEdwardsCurvePublic
from ._jsonwebkeyellipticcurvepublic import JSONWebKeyEllipticCurvePublic
from ._jsonwebkeyrsapublic import JSONKeyRSAPublic
from ._jsonwebkeysr25519public import JSONWebKeySR25519Public
from ._jsonwebkeysr25519private import JSONWebKeySR25519Private


__all__: list[str] = [
    'JSONWebKey',
    'JSONWebKeySR25519Public',
    'JSONWebKeySR25519Private',
]


JSONWebKeyPublicType = Union[
    JSONWebKeyEdwardsCurvePublic,
    JSONWebKeyEllipticCurvePublic,
    JSONKeyRSAPublic,
    JSONWebKeySR25519Public
]