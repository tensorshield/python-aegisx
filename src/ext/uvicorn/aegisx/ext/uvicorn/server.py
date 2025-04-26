import asyncio
import socket

import uvicorn


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