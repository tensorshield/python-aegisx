from pyasn1.type.char import IA5String
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.tag import Tag
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatSimple
from pyasn1.type.univ import Any
from pyasn1.type.univ import Choice
from pyasn1.type.univ import ObjectIdentifier


class GeneralName(Choice):
    componentType = NamedTypes(
        NamedType('rfc822Name', IA5String().subtype( # type: ignore
            implicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        ),
#            namedtype.NamedType('dNSName', univ.Any().subtype(
#                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
#            namedtype.NamedType('x400Address', univ.Any().subtype(
#                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        NamedType('directoryName', Any().subtype( # type: ignore
                implicitTag=Tag(tagClassContext, tagFormatSimple, 4)
            )
        ),
#            namedtype.NamedType('ediPartyName', univ.Any().subtype(
#                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
#            namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(
#                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
#            namedtype.NamedType('iPAddress', univ.OctetString().subtype(
#                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        NamedType('registeredID', ObjectIdentifier().subtype( # type: ignore
            implicitTag=Tag(tagClassContext, tagFormatSimple, 8)
        ))
    )