import copy
from typing import ClassVar


class OIDMapped:
    __source_mapping__: ClassVar[dict[tuple[str, str], str]]
    __oid__mapping__: ClassVar[dict[str, tuple[str, str]]]

    def __init_subclass__(cls) -> None:
        cls.__oid__mapping__ = copy.deepcopy(cls.__oid__mapping__)
        cls.__source_mapping__ = {v: k for k, v in cls.__oid__mapping__.items()}