from typing import Any
from typing import NotRequired
from typing import TypedDict

from libcanonical.types import Base64URLEncoded


JOSEHeaderDict = TypedDict('JOSEHeaderDict', {
    # RFC 7515
    "alg": NotRequired[str],
    "jku": NotRequired[str],
    "jwk": NotRequired[dict[str, Any]],
    "kid": NotRequired[str],
    "x5u": NotRequired[str],
    "x5c": NotRequired[list[str]],
    "x5t": NotRequired[str | Base64URLEncoded],
    "x5t_s256": NotRequired[str],
    "typ": NotRequired[str],
    "cty": NotRequired[str],
    "crit": NotRequired[list[str]]
})
