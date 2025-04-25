from typing import Union

from aegisx.backends.google.datastore import DatastoreStorage
from aegisx.ext.oauth.models import Grant
from aegisx.ext.oauth.client.repo import ClientRepository
from aegisx.ext.oauth.models import ClientConfiguration


class DatastoreClientRepository(ClientRepository):

    def __init__(
        self,
        storage: Union['DatastoreStorage', None] = None
    ):
        self.storage = storage or DatastoreStorage()

    async def grant(self, name: str) -> Grant | None:
        return await self.storage.get_model_by_key(Grant, name)

    async def get(self, name: str) -> ClientConfiguration | None:
        return await self.storage.get_model_by_key(ClientConfiguration, name)

    async def persist_client_config(
        self,
        obj: ClientConfiguration,
        *,
        name: str
    ) -> None:
        await self.storage.put(obj, pk=name)

    async def persist_grant(
        self,
        obj: Grant,
        *,
        name: str,
        config: ClientConfiguration
    ) -> None:
        await self.storage.put(obj, pk=name)