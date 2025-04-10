from typing import Any
from typing import AsyncIterable
from typing import Generic
from typing import Iterable
from typing import TypeVar

from aegisx.ext.jose import JSONWebKeySet

from aegisx.ext.iam.models import AuthorizedKey
from aegisx.ext.iam.models import Role
from aegisx.ext.iam.models import IAMAttachedPolicy
from aegisx.ext.iam.types import Permission


A = TypeVar(
    'A',
    bound=IAMAttachedPolicy[Any, Any, Any],
    default=IAMAttachedPolicy[Any, Any, Any]
)

R = TypeVar('R', bound=Role, default=Role)

T = TypeVar('T', bound=AuthorizedKey | IAMAttachedPolicy | Role)


class IAMRepository(Generic[A, R]):

    def roles(
        self,
        names: Iterable[str],
        limit: int = 25,
        page_token: str | None = None
    ) -> AsyncIterable[R]:
        raise NotImplementedError

    async def attached(self, targets: Iterable[str]) -> list[A]:
        raise NotImplementedError

    async def authorized_key(self, thumbprint: str) -> AuthorizedKey | None:
        raise NotImplementedError

    async def authorized_keys(self, email: str) -> JSONWebKeySet:
        raise NotImplementedError

    async def role(self, name: str) -> R | None:
        roles = [role async for role in self.roles([name])]
        return roles[0] if roles else None

    async def permissions(self, roles: list[str]) -> set[Permission]:
        permissions: set[Permission] = set()
        async for role in self.roles(roles):
            permissions.update(role.included_permissions)
        return permissions

    async def persist(self, instance: T) -> T:
        raise NotImplementedError(
            f"{type(self).__name__} can not persist "
            f"{type(instance).__name__} objects."
        )