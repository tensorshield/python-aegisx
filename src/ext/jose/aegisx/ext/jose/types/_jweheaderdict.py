from typing import NotRequired

from ._joseheaderdict import JOSEHeaderDict


class JWEHeaderDict(JOSEHeaderDict):
    enc: NotRequired[str]