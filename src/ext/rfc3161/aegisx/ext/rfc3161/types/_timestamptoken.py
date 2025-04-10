from typing import Any

from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType
from pyasn1.type.tag import Tag
from pyasn1.type.tag import tagClassContext
from pyasn1.type.tag import tagFormatConstructed
from pyasn1_modules.rfc2315 import ContentInfo
from pyasn1_modules.rfc2315 import SignedData
from pyasn1_modules.rfc2315 import signedData
from pyasn1.codec.ber import decoder

from ._timestampinfo import TSTInfo


class TimeStampToken(ContentInfo):
    componentType = NamedTypes(
        NamedType('contentType', signedData),
        OptionalNamedType(
            'content',
            SignedData().subtype( # type: ignore
                explicitTag=Tag(
                    tagClassContext,
                    tagFormatConstructed,
                    0
                )
            )
        )
    )

    @property
    def content(self) -> Any:
        return self[1] # type: ignore

    @property
    def tst_info(self) -> Any:
        x, substrate = decoder.decode( # type: ignore
            self.content['contentInfo']['content']
        )
        if substrate:
            raise ValueError('Incomplete decoding')
        x, substrate = decoder.decode(x, asn1Spec=TSTInfo()) # type: ignore
        if substrate:
            raise ValueError('Incomplete decoding')
        return x # type: ignore