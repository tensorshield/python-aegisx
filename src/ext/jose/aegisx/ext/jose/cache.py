from typing import TYPE_CHECKING

from libcanonical.utils import deephash

if TYPE_CHECKING:
    from .models import JSONWebToken


class JOSECache:
    seen: set[str]

    def __init__(self):
        self.seen = set()

    async def consume(self, jwt: 'JSONWebToken') -> None:
        if not jwt.jti: # pragma: no cover
            return
        v = deephash([jwt.jti, jwt.iss], using='sha256', encode='hex')
        if v in self.seen:
            raise ValueError('JSON Web Token (JWT) can not be replayed.')
        self.seen.add(v)