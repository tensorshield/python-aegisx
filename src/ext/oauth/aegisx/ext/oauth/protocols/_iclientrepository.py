import functools
from typing import overload
from typing import Any
from typing import Union
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegisx.ext.oauth.models import ClientConfiguration
    from aegisx.ext.oauth.models import Grant


class IClientRepository:

    async def get(self, name: str) -> Union['ClientConfiguration', None]:
        ...

    async def grant(
        self,
        name: str
    ) -> Union['Grant', None]:
        ...

    @overload
    async def persist(self, obj: 'ClientConfiguration', *, name: str) -> None:
        ...

    @overload
    async def persist(self, obj: 'Grant', *, name: str, config: 'ClientConfiguration') -> None:
        ...

    @functools.singledispatchmethod
    async def persist(
        self,
        obj: Union['ClientConfiguration', 'Grant'],
        *,
        name: str | None = None,
        **kwargs: Any
    ) -> None:
        ...