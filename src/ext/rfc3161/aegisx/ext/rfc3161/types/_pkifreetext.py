from pyasn1.type.char import UTF8String
from pyasn1.type.constraint import ValueSizeConstraint
from pyasn1.type.univ import Any
from pyasn1.type.univ import SequenceOf
from pyasn1_modules.rfc2459 import MAX


#class PKIFreeText(SequenceOf):
#    componentType = UTF8String # type: ignore
#    sizeSpec = SequenceOf.sizeSpec + ValueSizeConstraint(1, MAX) # type: ignore


class PKIFreeText(Any):
    pass