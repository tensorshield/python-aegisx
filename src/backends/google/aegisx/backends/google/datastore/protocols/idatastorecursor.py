from typing import Protocol
from typing import Iterator

from .idatastoreentity import IDatastoreEntity


class IDatastoreCursor(Protocol):
    __module__: str = 'canonical.ext.google.protocols'
    next_page_token: bytes | None
    num_results: int
    def __iter__(self) -> Iterator[IDatastoreEntity]: ...
    def __next__(self) -> IDatastoreEntity: ...