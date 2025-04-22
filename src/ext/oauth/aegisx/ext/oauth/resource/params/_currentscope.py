from typing import Annotated

import fastapi


async def get(request: fastapi.Request) -> set[str]:
    return getattr(request.state, 'scope', set())


CurrentScope = Annotated[
    set[str],
    fastapi.Depends(get)
]