import asyncio
import socket
import os
import sys

import uvicorn


STARTUP_FAILURE = 3


class Server(uvicorn.Server):
    """A :class:`uvicorn.Server` implementation that allows the injection
    of an :class:`asyncio.AbstractEventLoop`. For use cases where the event
    loop is started prior to the server.
    """

    def run(
        self,
        sockets: list[socket.socket] | None = None,
        loop: asyncio.AbstractEventLoop | None = None
    ) -> None:
        try:
            loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.serve(sockets=sockets))

    async def main(self):
        try:
            await self.serve(sockets=[self.config.bind_socket()])
        except KeyboardInterrupt:
            pass  # pragma: full coverage
        finally:
            if self.config.uds and os.path.exists(self.config.uds):
                os.remove(self.config.uds)  # pragma: py-win32

        if not self.started and not self.config.should_reload and self.config.workers == 1:
            sys.exit(STARTUP_FAILURE)

    def __await__(self):
        return self.main().__await__()