from typing import TypedDict

from ._permission import Permission


class RoleValidationContext(TypedDict):
    permissions: set[Permission]
    prefix: str