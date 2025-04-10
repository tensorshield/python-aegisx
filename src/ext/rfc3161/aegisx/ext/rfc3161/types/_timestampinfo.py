from typing import Any

from pyasn1.type.namedtype import DefaultedNamedType
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import Tag
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatSimple
from pyasn1.type.univ import Boolean
from pyasn1.type.univ import Integer
from pyasn1.type.univ import Sequence
from pyasn1.type.useful import GeneralizedTime
from pyasn1_modules.rfc2459 import Extensions

from ._accuracy import Accuracy
from ._generalname import GeneralName
from ._messageimprint import MessageImprint
from ._tsapolicyid import TSAPolicyID


class TSTInfo(Sequence):
    componentType = NamedTypes(
        NamedType(
            'version',
            Integer(namedValues=NamedValues(('v1', 1)))
        ),
        OptionalNamedType('policy', TSAPolicyID()),
        NamedType('messageImprint', MessageImprint()),
        NamedType('serialNumber', Integer()),
        NamedType('genTime', GeneralizedTime()),
        OptionalNamedType('accuracy', Accuracy()),
        DefaultedNamedType('ordering', Boolean(False)),
        OptionalNamedType('nonce', Integer()),
        OptionalNamedType(
            'tsa',
            GeneralName().subtype( # type: ignore
                explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            )
        ),
        OptionalNamedType(
            'extensions',
            Extensions().subtype( # type: ignore
                implicitTag=Tag(tagClassContext, tagFormatSimple, 1))
            )
    )

    @property
    def version(self) -> Any:
        return self[0] # type: ignore

    @property
    def policy(self) -> Any:
        return self[1] # type: ignore

    @property
    def message_imprint(self) -> Any:
        return self[2] # type: ignore