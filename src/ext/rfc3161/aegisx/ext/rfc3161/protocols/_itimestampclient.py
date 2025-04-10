from typing import Literal
from typing import Protocol
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegisx.ext.rfc3161.models import TimestampToken


class ITimestampClient(Protocol):

    async def timestamps(
        self,
        data: bytes,
        algorithm: Literal['sha256', 'sha384', 'sha512'] = 'sha256',
        timeout: int = 60
    ) -> list['TimestampToken']:
        ...