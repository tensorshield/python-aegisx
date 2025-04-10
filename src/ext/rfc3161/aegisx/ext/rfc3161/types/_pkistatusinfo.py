from pyasn1.type.univ import Sequence
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType

from ._pkifreetext import PKIFreeText
from ._pkistatus import PKIStatus
from ._pkifailureinfo import PKIFailureInfo


class PKIStatusInfo(Sequence):
    componentType = NamedTypes(
        NamedType('status', PKIStatus()),
        OptionalNamedType('statusString', PKIFreeText()),
        OptionalNamedType('failInfo', PKIFailureInfo())
    )