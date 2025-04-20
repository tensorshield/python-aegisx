from typing import Any
from typing import NotRequired
from typing import TypedDict

from libcanonical.types import Base64URLEncoded


JWSHeaderDict = TypedDict('JWSHeaderDict', {
    # RFC 7515
    "alg": NotRequired[str],
    "jku": NotRequired[str],
    "jwk": NotRequired[dict[str, Any]],
    "kid": NotRequired[str],
    "x5u": NotRequired[str],
    "x5c": NotRequired[list[str]],
    "x5t": NotRequired[str | Base64URLEncoded],
    "x5t#S256": NotRequired[str],
    "typ": NotRequired[str],
    "cty": NotRequired[str],
    "crit": NotRequired[list[str]]
})
