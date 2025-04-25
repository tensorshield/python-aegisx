import asyncio
import contextlib
import functools
import os
import threading
from typing import cast
from typing import Any
from typing import AsyncIterable
from typing import Callable
from typing import Iterable
from typing import Mapping
from typing import TypeVar

import pydantic
from google.api_core.exceptions import InvalidArgument
from google.auth.credentials import Credentials
from google.cloud.datastore import Client
from google.cloud.datastore import Entity

from .protocols import IDatastoreKey
from .protocols import IDatastoreEntity
from .protocols import IDatastoreTransaction
from ._cursor import DatastoreCursor

T = TypeVar('T', bound=pydantic.BaseModel)

# TODO: Probably does not play well with forking.
_local = threading.local()


class DatastoreStorage:
    __module__: str = 'canonical.ext.google.datastore'
    dump_mode: str = 'protobuf'
    exclude_fields: set[str] = set()
    exclude_none: bool = True
    namespace: str | None

    @staticmethod
    async def run_in_executor(
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any
    ) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args, **kwargs)

    @staticmethod
    def default_client(
        project: str | None = None,
        namespace: str | None = None,
        database: str | None = None,
        credentials: Credentials | None = None
    ) -> Client:
        if not hasattr(_local, 'client'):
            _local.client = Client(
                credentials=credentials,
                project=project or os.getenv('GOOGLE_DATASTORE_PROJECT'),
                namespace=namespace or os.getenv('GOOGLE_DATASTORE_NAMESPACE'),
                database=database or os.getenv('GOOGLE_DATASTORE_DATABASE')
            )
        return getattr(_local, 'client')

    def __init__( # type: ignore
        self,
        *,
        client: Client | None = None,
        credentials: Credentials | None = None,
        project: str | None = None,
        namespace: str | None = None,
        database: str | None = None
    ) -> None:
        if client is None:
            client = self.default_client(
                project=project,
                namespace=namespace,
                credentials=credentials,
                database=database
            )
        self.client = client
        self.namespace = namespace

    async def allocate_identifier(self, cls: type | str, namespace :str | None = None) -> int:
        if not isinstance(cls, str):
            cls = cls.__name__
        base = self.entity_key(kind=cls, namespace=namespace)
        result = await self.run_in_executor(
            functools.partial( # type: ignore
                self.client.allocate_ids, # type: ignore
                incomplete_key=base,
                num_ids=1
            )
        )
        return [x for x in result][0].id

    def dump_model(
        self,
        obj: pydantic.BaseModel,
        exclude_fields: set[str] | dict[str, Any] | None = None,
        exclude_none: bool = False
    ) -> dict[str, Any]:
        return obj.model_dump(
            mode=self.dump_mode,
            exclude=exclude_fields or self.exclude_fields,
            exclude_none=exclude_none or self.exclude_none
        )

    def entity_factory(
        self,
        key: IDatastoreKey,
        obj: pydantic.BaseModel,
        exclude_fields: set[str] | dict[str, Any] | None = None,
        noindex: Iterable[str] | None = None
    ) -> IDatastoreEntity:
        noindex = set(noindex or getattr(obj, '__noindex__', []))
        entity = cast(
            IDatastoreEntity,
            self.client.entity(key, exclude_from_indexes=tuple(set(noindex or [])))  # type: ignore
        )
        return self.entity_from_dict(entity, self.dump_model(obj), noindex)

    def entity_from_dict(
        self,
        root: IDatastoreEntity,
        values: dict[str, Any], 
        noindex: Iterable[str],
        parent: str | None = None
    ):
        for attname, value in values.items():
            path = attname if not parent else f'{parent}.{attname}'
            if isinstance(value, dict):
                root[attname] = self.entity_from_dict(
                    cast(IDatastoreEntity, Entity()),
                    values=cast(dict[str, Any], value),
                    noindex=noindex,
                    parent=path
                )
                continue
            if path in noindex or parent and parent in noindex:
                root.exclude_from_indexes.add(attname)
            root[attname] = value
        return root

    def entity_key(
        self,
        kind: str | type,
        identifier: int | str | None = None,
        parent: IDatastoreKey | None = None,
        namespace: str | None = None
    ) -> IDatastoreKey:
        if not isinstance(kind, str):
            kind = self.get_entity_name(kind)
        args: list[Any] = [kind]
        if identifier is not None:
            args.append(identifier)
        return self.client.key(*args, parent=parent, namespace=namespace or self.namespace) # type: ignore

    def get_entity_name(self, cls: type[Any]) -> str:
        return cls.__name__

    def get_namespace(self) -> str:
        raise NotImplementedError

    def model_factory(self, entity: Mapping[str, Any], model: type[T]) -> T:
        obj = model.model_validate(dict(entity))
        return obj

    def query(
        self,
        model: type[T],
        filters: Iterable[tuple[str, str, Any]] | None = None,
        sort: Iterable[str] | None = None,
        namespace: str | None = None,
        limit: int | None = None,
        kind: str | None = None,
        page_size: int = 10,
        keys: list[IDatastoreKey] | None = None,
        **_: Any
    ) -> DatastoreCursor[T]:
        flattened: list[tuple[str, str, Any]] = []
        for attname, op, value in list(filters or []):
            if not isinstance(value, list):
                flattened.append((attname, op, value))
                continue
            flattened.extend([(attname, op, x) for x in value]) # type: ignore
        return DatastoreCursor(
            kind=kind or self.get_entity_name(model),
            model=model,
            client=self.client,
            keys=keys,
            filters=flattened,
            namespace=namespace or self.namespace,
            sort=sort,
            limit=limit,
            page_size=page_size
        )

    async def find(
        self,
        kind: type[T],
        filters: Iterable[tuple[str, str, int | str]],
        sort: Iterable[str] | None = None
    ) -> AsyncIterable[T]:
        q = self.client.query(kind=kind.__name__) # type: ignore
        if sort is not None:
            q.order = sort
        for filter in filters:
            q.add_filter(*filter) # type: ignore
        results = await self.run_in_executor(
            functools.partial(q.fetch) # type: ignore
        )
        for entity in results:
            yield kind.model_validate(dict(entity))

    async def get_entity_by_key(self, key: IDatastoreKey) -> IDatastoreEntity | None:
        return await self.run_in_executor(
            functools.partial(
                self.client.get, # type: ignore
                key=key
            )
        )

    async def get_model_by_key(
        self,
        cls: type[T],
        pk: int | str,
        parent: IDatastoreKey | None = None,
        namespace: str | None = None,
        factory: Callable[[dict[str, Any], type[T]], T] | None = None
    ) -> T | None:
        factory = factory or self.model_factory
        entity = await self.get_entity_by_key(
            key=self.entity_key(cls, pk, parent=parent, namespace=namespace)
        )
        if entity is None:
            return None
        return await self.restore(factory(dict(entity), cls))

    async def put(
        self,
        obj: pydantic.BaseModel,
        pk: int | str,
        parent: IDatastoreKey | None = None,
        exclude_fields: set[str] | dict[str, Any] | None = None,
        transaction: IDatastoreTransaction | None = None,
        namespace: str | None = None,
        noindex: Iterable[str] | None = None
    ) -> IDatastoreKey:
        put = self.client.put if transaction is None else transaction.put # type: ignore
        key = self.entity_key(type(obj), pk, parent=parent, namespace=namespace)
        entity = self.entity_factory(
            key=key,
            obj=obj,
            exclude_fields=exclude_fields,
            noindex=noindex
        )
        try:
            await self.run_in_executor(put, entity) # type: ignore
        except InvalidArgument as e:
            raise TypeError(e.message) # type: ignore
        return entity.key # type: ignore

    async def restore(self, instance: T) -> T:
        return instance 

    @contextlib.asynccontextmanager
    async def transaction(self, transaction: Any | None = None):
        if transaction is not None:
            raise NotImplementedError(
                'Subtransaction are not supported with Google Datastore'
            )
        tx = cast(IDatastoreTransaction, await self.run_in_executor(self.client.transaction)) # type: ignore
        await self.run_in_executor(tx.__enter__)
        try:
            yield tx
        except Exception as e:
            await self.run_in_executor(tx.__exit__, type(e), e, None)
            raise
        await self.run_in_executor(tx.__exit__, None, None, None)