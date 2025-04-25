from typing import Protocol


class IDatastoreKey(Protocol):
    __module__: str = 'canonical.ext.google.protocols'
    flat_path: tuple[int | str, ...]
    id: int
    name: str
    path: list[dict[str, int | str]]