import inspect
from typing import cast
from typing import Awaitable

from dependency_injector import containers

__all__: list[str] = [
    'Container',
    'DeclarativeContainer'
]


class SetupMixin:
    """Mixin class that exposes the :meth:`setup()` method to automatically
    wire a :class:`~dependency_injector.Container` instance.
    """
    package_name: str

    @classmethod
    async def setup(cls):
        container = cast(containers.Container, cls())
        result = cast(Awaitable[None] | None, await container.init_resources()) # type: ignore
        if inspect.isawaitable(result):
            await result
        container.wire(packages=[cls.package_name])
        return container


class Container(containers.Container, SetupMixin):
    pass



class DeclarativeContainer(containers.DeclarativeContainer, SetupMixin):
    pass