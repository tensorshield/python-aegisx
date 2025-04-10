from typing import Literal
from typing import TypedDict


class ValidationContext(TypedDict):
    op: Literal['create']