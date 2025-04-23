import functools
from typing import overload
from typing import Any

from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import TokenResponse


class ClientRepository:

    async def grant(
        self,
        client_id: str
    ) -> TokenResponse | None:
        """Lookup a grant from the persistent data storage."""
        raise NotImplementedError

    @overload
    async def persist(self, obj: ClientConfiguration) -> None:
        ...

    @overload
    async def persist(self, obj: TokenResponse, config: ClientConfiguration) -> None:
        ...

    @functools.singledispatchmethod
    async def persist(
        self,
        obj: ClientConfiguration | TokenResponse,
        *args: Any
    ) -> None:
        raise NotImplementedError(f'Can not persist {type(obj).__name__}')

    async def persist_client_config(self, obj: ClientConfiguration) -> None:
        raise NotImplementedError

    async def persist_grant(self, obj: TokenResponse, config: ClientConfiguration) -> None:
        raise NotImplementedError

    @persist.register # type: ignore
    async def _(self, obj: ClientConfiguration, *args: Any):
        return await self.persist_client_config(obj)

    @persist.register # type: ignore
    async def _(self, obj: TokenResponse, config: ClientConfiguration):
        return await self.persist_grant(obj, config)