from pyasn1.type.namedval import NamedValues
from pyasn1.type.univ import BitString


class PKIFailureInfo(BitString):
    namedValues = NamedValues(
        ('badAlg', 0),
        # unrecognized or unsupported Algorithm Identifier
        ('badRequest' ,2),
        # transaction not permitted or supported
        ('badDataFormat' ,5),
        # the data submitted has the wrong format
        ('timeNotAvailable' ,14),
        # the TSA's time source is not available
        ('unacceptedPolicy' ,15),
        # the requested TSA policy is not supported by the TSA
        ('unacceptedExtension' ,16),
        # the requested extension is not supported by the TSA
        ('addInfoNotAvailable' ,17),
        # the additional information requested could not be understood
        # or is not available
        ('systemFailure' ,25))
        # the request cannot be handled due to system failure  }