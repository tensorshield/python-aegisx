from typing import Any
from typing import NotRequired
from typing import TypedDict


JWSHeaderDict = TypedDict('JWSHeaderDict', {
    # RFC 7515
    "alg": NotRequired[str],
    "jku": NotRequired[str],
    "jwk": NotRequired[dict[str, Any]],
    "kid": NotRequired[str],
    "x5u": NotRequired[str],
    "x5c": NotRequired[list[str]],
    "x5t": NotRequired[str],
    "x5t#S256": NotRequired[str],
    "typ": NotRequired[str],
    "cty": NotRequired[str],
    "crit": NotRequired[list[str]]
})
