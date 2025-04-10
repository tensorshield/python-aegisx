from typing import cast

from pyasn1.type.univ import Sequence
from pyasn1.type.namedtype import NamedType
from pyasn1.type.namedtype import NamedTypes
from pyasn1.type.namedtype import OptionalNamedType

from ._pkistatusinfo import PKIStatusInfo
from ._timestamptoken import TimeStampToken


class TimeStampResponse(Sequence):
    componentType = NamedTypes(
        NamedType('status', PKIStatusInfo()),
        OptionalNamedType('timeStampToken', TimeStampToken())
    )

    @property
    def status(self) -> PKIStatusInfo:
        return cast(PKIStatusInfo, self[0]) # type: ignore

    @property
    def time_stamp_token(self) -> TimeStampToken:
        return self[1] # type: ignore