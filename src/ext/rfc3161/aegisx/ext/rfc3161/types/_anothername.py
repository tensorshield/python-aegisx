from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType
from pyasn1.type.tag import Tag
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatSimple
from pyasn1.type.univ import Any
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.type.univ import Sequence


class AnotherName(Sequence):
    componentType = NamedTypes(
        OptionalNamedType('type-id', ObjectIdentifier()),
        OptionalNamedType(
            'value',
            Any().subtype( # type: ignore
                explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            )
        )
    )