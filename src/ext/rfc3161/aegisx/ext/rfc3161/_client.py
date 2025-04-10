import asyncio
import hashlib
import random
from typing import cast
from typing import Any
from typing import Literal

import httpx
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1_modules.rfc2459 import AlgorithmIdentifier

from .const import TIMESTAMP_SERVERS
from .models import TimestampToken
from .types import MessageImprint
from .types import TimestampAuthority
from .types import TimeStampRequest
from .types import TimeStampResponse


class TimestampClient(httpx.AsyncClient):
    _hash_oids: dict[str, ObjectIdentifier] = {
        'sha256': ObjectIdentifier((2,16,840,1,101,3,4,2,1,)),
        'sha384': ObjectIdentifier((2,16,840,1,101,3,4,2,2,)),
        'sha512': ObjectIdentifier((2,16,840,1,101,3,4,2,3,))
    }

    def __init__(
        self,
        using: set[str | TimestampAuthority] | None = None
    ):
        super().__init__()
        self.using = {
            str(x.value) if isinstance(x, TimestampAuthority) else x
            for x in (using or [])
        }

    def get_hash_oid(self, alg: str):
        return self._hash_oids[alg]

    def select(self, k: int = 3):
        if self.using:
            return self.using
        servers: set[str] = set()
        while len(servers) != k:
            servers.update(
                random.choices(
                    population=[x[0] for x in TIMESTAMP_SERVERS],
                    weights=[x[1] for x in TIMESTAMP_SERVERS],
                    k=k
                )
            )
        return servers

    async def timestamps(
        self,
        data: bytes,
        algorithm: Literal['sha256', 'sha384', 'sha512'] = 'sha256',
        timeout: int = 60
    ) -> list[TimestampToken]:
        return await asyncio.gather(*[
            self.timestamp(url=url, data=data, algorithm=algorithm, timeout=timeout)
            for url in self.select(k=3)
        ])

    async def timestamp(
        self,
        url: str,
        data: bytes,
        algorithm: Literal['sha256', 'sha384', 'sha512'] = 'sha256',
        timeout: int = 60
    ) -> TimestampToken:
        h = hashlib.new(algorithm)
        h.update(data)
        digest = h.digest()

        algorithm_id = AlgorithmIdentifier()
        algorithm_id.setComponentByPosition(0, self.get_hash_oid(algorithm)) # type: ignore
        message_imprint = MessageImprint()
        message_imprint.setComponentByPosition(0, algorithm_id) # type: ignore
        message_imprint.setComponentByPosition(1, digest) # type: ignore
        request = TimeStampRequest()
        request.setComponentByPosition(0, 'v1') # type: ignore
        request.setComponentByPosition(1, message_imprint) # type: ignore
        request.setComponentByPosition(4) # type: ignore

        response = await self.post(
            url=url,
            content=encoder.encode(request), # type: ignore
            headers={
                'Content-Type': 'application/timestamp-query'
            },
            follow_redirects=True,
            timeout=timeout
        )
        if response.status_code != 200:
            raise ValueError(
                f"Timestamp server {url} return a non-200 response: {response.status_code}"
            )
        substrate: Any
        tst, substrate = decoder.decode(response.content, asn1Spec=TimeStampResponse()) # type: ignore
        tst = cast(TimeStampResponse, tst)
        if substrate:
            raise ValueError(
                f"Timestamp server {url} return a malformed response."
            )
        if str(tst.status[0]) != 'granted': # type: ignore
            raise ValueError(
                f'The Timestamping Authority (TSA) did not return a '
                f'token: {tst.status[0]}'
            )
        return TimestampToken.fromresponse(
            tst, # type: ignore
            url=url,
            digest=digest
        )