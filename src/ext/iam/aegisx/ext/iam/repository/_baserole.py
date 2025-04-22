from typing import Generic
from typing import Iterable
from typing import TypeVar

from aegisx.ext.iam.models import Role
from aegisx.ext.iam.types import Permission
from aegisx.ext.iam.types import WildcardPermission

R = TypeVar('R', bound=Role, default=Role)


class IAMRoleRepository(Generic[R]):

    async def get(self, name: str) -> R | None:
        raise NotImplementedError

    async def filter(self, names: Iterable[str]) -> list[R]:
        raise NotImplementedError

    async def permissions(
        self,
        names: Iterable[str]
    ) -> set[Permission | WildcardPermission]:
        raise NotImplementedError