from typing import Any
from typing import Callable
from typing import Generic
from typing import Optional
from typing import TypeVar


T = TypeVar('T')


class classproperty(property, Generic[T]):
    fget: Callable[[Any], T] | None

    def __init__(self, fget: Callable[[Any], T], *arg: Any, **kw: Any):
        super().__init__(fget, *arg, **kw)
        self.__doc__ = fget.__doc__

    def __get__(self, obj: Any, cls: Optional[type] = None) -> Any:
        assert self.fget is not None
        return self.fget(cls)