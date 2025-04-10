from typing import TypedDict


class JWSCompactSerializationDict(TypedDict):
    protected: str
    payload: str
    signature: str