from pyasn1_modules.rfc2459 import AlgorithmIdentifier
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.univ import OctetString
from pyasn1.type.univ import Sequence


class MessageImprint(Sequence):
    componentType = NamedTypes(
        NamedType('hashAlgorithm', AlgorithmIdentifier()),
        NamedType('hashedMessage', OctetString())
    )

    @property
    def hash_algorithm(self) -> str:
        return self[0] # type: ignore

    @property
    def hashed_message(self) -> bytes:
        return self[1] # type: ignore