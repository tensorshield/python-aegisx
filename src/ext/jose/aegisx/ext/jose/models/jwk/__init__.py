from typing import Union

from ._jsonwebkey import JSONWebKey
from ._jsonwebkeyedwardscurvepublic import JSONWebKeyEdwardsCurvePublic
from ._jsonwebkeyedwardscurveprivate import JSONWebKeyEdwardsCurvePrivate
from ._jsonwebkeyellipticcurvepublic import JSONWebKeyEllipticCurvePublic
from ._jsonwebkeyellipticcurveprivate import JSONWebKeyEllipticCurvePrivate
from ._jsonwebkeyrsapublic import JSONKeyRSAPublic
from ._jsonwebkeyrsaprivate import JSONKeyRSAPrivate
from ._jsonwebkeysr25519public import JSONWebKeySR25519Public
from ._jsonwebkeysr25519private import JSONWebKeySR25519Private
from ._symmetricencryptionkey import SymmetricEncryptionKey
from ._symmetricsigningkey import SymmetricSigningKey


__all__: list[str] = [
    'JSONWebKey',
    'JSONWebKeyPrivateType',
    'JSONWebKeyPublicType',
    'JSONWebKeyEdwardsCurvePrivate',
    'JSONWebKeyEllipticCurvePrivate',
    'JSONKeyRSAPrivate',
    'JSONWebKeySR25519Public',
    'JSONWebKeySR25519Private',
    'SymmetricEncryptionKey',
    'SymmetricSigningKey',
]


JSONWebKeyPublicType = Union[
    JSONWebKeyEdwardsCurvePublic,
    JSONWebKeyEllipticCurvePublic,
    JSONKeyRSAPublic,
    JSONWebKeySR25519Public
]

JSONWebKeyPrivateType = Union[
    JSONWebKeyEdwardsCurvePrivate,
    JSONWebKeyEllipticCurvePrivate,
    JSONKeyRSAPrivate,
    JSONWebKeySR25519Private,
    SymmetricEncryptionKey,
    SymmetricSigningKey
]