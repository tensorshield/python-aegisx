from pyasn1.type.namedtype import DefaultedNamedType
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatSimple
from pyasn1.type.tag import Tag
from pyasn1.type.univ import Boolean
from pyasn1.type.univ import Integer
from pyasn1.type.univ import Sequence
from pyasn1_modules.rfc2459 import Extensions

from ._messageimprint import MessageImprint
from ._tsapolicyid import TSAPolicyID


class TimeStampRequest(Sequence):
    componentType = NamedTypes(
            NamedType('version',
                Integer(namedValues=NamedValues(('v1', 1)))),
            NamedType('messageImprint', MessageImprint()),
            OptionalNamedType('reqPolicy', TSAPolicyID()),
            OptionalNamedType('nonce', Integer()),
            DefaultedNamedType('certReq', Boolean(False)),
            OptionalNamedType('extensions',
                Extensions().subtype( # type: ignore
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            ))
        )