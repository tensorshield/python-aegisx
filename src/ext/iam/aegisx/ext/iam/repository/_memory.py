from typing import cast
from typing import Any
from typing import AsyncIterable
from typing import Generic
from typing import Iterable
from typing import TypeVar

from aegisx.ext.jose import JSONWebKeySet

from aegisx.ext.iam.models import AuthorizedKey
from aegisx.ext.iam.models import Role
from aegisx.ext.iam.models import IAMAttachedPolicy
from ._base import IAMRepository


A = TypeVar(
    'A',
    bound=IAMAttachedPolicy[Any, Any, Any],
    default=IAMAttachedPolicy[Any, Any, Any]
)

R = TypeVar('R', bound=Role[Any], default=Role[Any])

T = TypeVar('T', bound=IAMAttachedPolicy[Any, Any, Any] | Role)


class MemoryIAMRepository(IAMRepository[A, R], Generic[A, R]): # pragma: no cover
    __roles: dict[str, R]
    __policies: dict[str, A]
    __authorized_keys: dict[str, AuthorizedKey]

    def __init__(self) -> None:
        self.__authorized_keys = {}
        self.__roles = {}
        self.__policies = {}

    async def attached(self, targets: Iterable[str]) -> list[A]:
        return [
            self.__policies[t]
            for t in targets
            if t in self.__policies
        ]

    async def authorized_keys(self, email: str) -> JSONWebKeySet:
        keys = filter(lambda x: x.email == email, self.__authorized_keys.values())
        return JSONWebKeySet(keys=[x.key for x in keys])

    async def roles(
        self,
        names: Iterable[str],
        limit: int = 25,
        page_token: str | None = None
    ) -> AsyncIterable[R]:
        n = 0
        for name in sorted(names):
            if name not in self.__roles:
                continue
            yield self.__roles[name]
            n += 1
            if n == limit:
                break

    async def persist(self, instance: T) -> T:
        if isinstance(instance, Role):
            self.__roles[instance.name] = cast(R, instance)
        if isinstance(instance, IAMAttachedPolicy):
            self.__policies[instance.target] = cast(A, instance)
        return instance