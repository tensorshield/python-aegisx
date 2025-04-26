from typing import Callable
from typing import Literal

from uvicorn.importer import import_from_string


LoopSetupType = Literal["none", "auto", "asyncio", "uvloop"]


LOOP_SETUPS: dict[LoopSetupType, str | None] = {
    "none": None,
    "auto": "uvicorn.loops.auto:auto_loop_setup",
    "asyncio": "uvicorn.loops.asyncio:asyncio_setup",
    "uvloop": "uvicorn.loops.uvloop:uvloop_setup",
}


def setup_event_loop(loop: LoopSetupType, use_subprocess: bool = False) -> None:
    loop_setup: Callable[..., None] | None = import_from_string(LOOP_SETUPS[loop])
    if loop_setup is not None:
        loop_setup(use_subprocess=use_subprocess)