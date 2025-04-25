import functools
from typing import overload
from typing import Any

from aegisx.ext.oauth.protocols import IClientRepository
from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import Grant
from aegisx.ext.oauth.models import TokenResponse


class ClientRepository(IClientRepository):

    async def grant(
        self,
        name: str
    ) -> Grant | None:
        """Lookup a grant from the persistent data storage."""
        raise NotImplementedError

    async def get(self, name: str) -> ClientConfiguration | None:
        raise NotImplementedError

    @overload
    async def persist(self, obj: ClientConfiguration, *, name: str) -> None:
        ...

    @overload
    async def persist(self, obj: Grant, *, name: str, config: ClientConfiguration) -> None:
        ...

    @functools.singledispatchmethod
    async def persist(
        self,
        obj: ClientConfiguration | TokenResponse,
        *,
        name: str | None = None,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError(f'Can not persist {type(obj).__name__}')

    async def persist_client_config(self, obj: ClientConfiguration, *, name: str) -> None:
        raise NotImplementedError

    async def persist_grant(self, obj: Grant, *, name: str, config: ClientConfiguration) -> None:
        raise NotImplementedError

    @persist.register # type: ignore
    async def _(self, obj: ClientConfiguration, *, name: str):
        return await self.persist_client_config(obj, name=name)

    @persist.register # type: ignore
    async def _(self, obj: Grant, name: str, config: ClientConfiguration):
        return await self.persist_grant(obj, name=name, config=config)