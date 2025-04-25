import asyncio
import datetime
import functools
from typing import cast
from typing import Any
from typing import AsyncIterator
from typing import Generic
from typing import Iterable
from typing import Mapping
from typing import TypeVar

import pydantic
from google.cloud.datastore import Client
from google.cloud.datastore.query import PropertyFilter

from .protocols import IDatastoreCursor
from .protocols import IDatastoreQuery
from .protocols import IDatastoreKey
from .protocols import IDatastoreEntity


T = TypeVar('T')


class DatastoreCursor(Generic[T]):
    __module__: str = 'canonical.ext.google.datastore'
    _client: Client
    _filters: Iterable[tuple[str, str, int | str | datetime.datetime]]
    _keys_only: bool
    _keys: list[IDatastoreKey]
    _kind: str
    _limit: int | None
    _loop: asyncio.AbstractEventLoop
    _model: type[pydantic.BaseModel]
    _sort: list[str]

    def __init__(
        self,
        kind: str,
        model: type[T],
        client: Client,
        keys: list[IDatastoreKey] | None = None,
        filters: Iterable[tuple[str, str, int | str | datetime.datetime]] | None = None,
        namespace: str | None = None,
        sort: Iterable[str] | None = None,
        page_size: int = 1000,
        limit: int | None = None,
        _keys_only: bool = False
    ):
        self._client = client
        self._filters = filters or []
        self._keys_only = _keys_only
        self._keys = keys or []
        self._kind = kind
        self._limit = limit
        self._loop = asyncio.get_running_loop()
        self._model = cast(type[pydantic.BaseModel], model)
        self._namespace = namespace
        self._page_size = page_size
        self._sort = list(sort or [])

    def factory(self, entity: IDatastoreEntity):
        return cast(T, self._model.model_validate(dict(entity)))

    def model_factory(self, entity: Mapping[str, Any] | IDatastoreEntity):
        return self._model.model_validate(entity)

    def keys(self, page_size: int | None = None, limit: int | None = None) -> 'EntityKeyDatastoreCursor':
        return EntityKeyDatastoreCursor(
            kind=self._kind,
            model=self._model, # type: ignore
            client=self._client,
            keys=self._keys,
            filters=self._filters,
            sort=self._sort,
            page_size=page_size or self._page_size,
            limit=limit or self._limit,
            namespace=self._namespace,
            _keys_only=True
        )

    def get_query(self) -> IDatastoreQuery:
        return cast(
            IDatastoreQuery,
            self._client.query(kind=self._kind, namespace=self._namespace) # type: ignore
        )

    async def all(self) -> AsyncIterator[T]:
        cursor: bytes | None = None
        while True:
            c = await self.run_query(limit=self._page_size, page=cursor)
            objects = list(c)
            if not objects:
                break
            for entity in objects:
                yield self.factory(entity)
            if self._keys:
                # TODO: It is assumed here that with a keys query, all objects
                # are returned in one call.
                break
            if not c.next_page_token:
                break
            cursor = c.next_page_token

    async def exists(self) -> bool:
        return await self.keys().first() is not None

    async def first(self) -> T | None:
        c = await self.run_query(limit=1)
        objects = list(c)
        if not objects:
            return None
        return self.factory(objects[0])

    async def one(self) -> T:
        c = await self.run_query(limit=2)
        objects = list(c)
        if len(objects) > 1:
            raise ValueError("Multiple objects returned.")
        if not objects:
            raise ValueError("No object matches the search query.")
        return self.factory(objects[0])

    async def run_query(self, limit: int | None = None, page: bytes | None = None) -> IDatastoreCursor:
        if self._keys:
            f = functools.partial(self._client.get_multi, self._keys) # type: ignore
        else:
            q = self.get_query()
            for attname, op, value in self._filters:
                q.add_filter(filter=PropertyFilter(attname, op, value)) # type: ignore
            if self._sort:
                q.order = self._sort
            f = functools.partial(q.fetch, start_cursor=page, limit=limit)
        return await self._loop.run_in_executor(None, f) # type: ignore

    async def __aiter__(self):
        async for obj in self.all():
            yield obj

    def __await__(self):
        return self._iterall().__await__()

    async def _iterall(self):
        return [x async for x in self]


class EntityKeyDatastoreCursor(DatastoreCursor[IDatastoreKey]): # type: ignore

    def factory(self, entity: IDatastoreEntity) -> IDatastoreKey:
        return entity.key

    def get_query(self) -> IDatastoreQuery:
        q = super().get_query()
        q.keys_only()
        return q