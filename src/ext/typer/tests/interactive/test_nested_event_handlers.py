import threading

from aegisx.ext.typer import AsyncTyper


event = threading.Event()


async def handler():
    event.set()


app = AsyncTyper()
app.add_event_handler('startup', handler)
subcommand = AsyncTyper()

app.add_typer(subcommand)


@subcommand.async_command(name='test')
async def f():
    pass


try:
    app()
finally:
    assert event.is_set()