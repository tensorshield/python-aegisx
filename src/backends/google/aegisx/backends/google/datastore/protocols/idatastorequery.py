from typing import Any
from typing import Protocol


class IDatastoreQuery(Protocol):
    __module__: str = 'canonical.ext.google.protocols'
    order: list[str]
    def add_filter(self, attname: str, op: str, value: Any) -> None: ...
    def keys_only(self) -> bool: ...
    def fetch(self, *args: Any, **kwargs: Any) -> None: ...