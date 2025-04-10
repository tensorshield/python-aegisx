from typing import NotRequired
from typing import TypedDict

from ._jwsheaderdict import JWSHeaderDict


class SignerDict(TypedDict):
    protected: str
    header: NotRequired[JWSHeaderDict]
    signature: str


class JWSGeneralSerializationDict(TypedDict):
    payload: str
    signatures: list[SignerDict]