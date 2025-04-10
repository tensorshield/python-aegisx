from typing import TypedDict

from ._jwsheaderdict import JWSHeaderDict


class JWSFlattenedSerializationDict(TypedDict):
    protected: str
    header: JWSHeaderDict
    payload: str
    signature: str