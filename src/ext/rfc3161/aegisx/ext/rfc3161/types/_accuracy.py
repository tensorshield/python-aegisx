from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType
from pyasn1.type.tag import Tag
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatSimple
from pyasn1.type.univ import Integer
from pyasn1.type.univ import Sequence


class Accuracy(Sequence):
    componentType = NamedTypes(
        OptionalNamedType('seconds', Integer()),
        OptionalNamedType(
            'millis',
            Integer().subtype(  # type: ignore
                implicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            )
        ),
        OptionalNamedType(
            'micros', Integer().subtype( # type: ignore
                implicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        )
    )