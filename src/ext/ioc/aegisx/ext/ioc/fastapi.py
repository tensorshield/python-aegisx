from dependency_injector.wiring import ClassGetItemMeta
from dependency_injector.wiring import Provide
try:
    import fastapi.params


    class Depends(fastapi.params.Depends, metaclass=ClassGetItemMeta): # type: ignore

        def __init__(self, qualname: str):
            super().__init__(
                dependency=Provide[qualname],
                use_cache=True
            )
except ImportError:

    class Depends(metaclass=ClassGetItemMeta):

        def __init__(self, qualname: str):
            raise ImportError("The fastapi package is not installed.")