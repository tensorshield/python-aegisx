import asyncio
from collections import defaultdict
from functools import wraps
from typing import Any
from typing import Callable
from typing import Literal

# TODO: This is a literal copy of typer.__init__
from shutil import get_terminal_size as get_terminal_size

from click.exceptions import Abort as Abort
from click.exceptions import BadParameter as BadParameter
from click.exceptions import Exit as Exit
from click.termui import clear as clear
from click.termui import confirm as confirm
from click.termui import echo_via_pager as echo_via_pager
from click.termui import edit as edit
from click.termui import getchar as getchar
from click.termui import launch as launch
from click.termui import pause as pause
from click.termui import progressbar as progressbar
from click.termui import prompt as prompt
from click.termui import secho as secho
from click.termui import style as style
from click.termui import unstyle as unstyle
from click.utils import echo as echo
from click.utils import format_filename as format_filename
from click.utils import get_app_dir as get_app_dir
from click.utils import get_binary_stream as get_binary_stream
from click.utils import get_text_stream as get_text_stream
from click.utils import open_file as open_file

from typer import colors as colors
from typer.main import Typer as Typer
from typer.main import run as run
from typer.models import CallbackParam as CallbackParam
from typer.models import Context as Context
from typer.models import FileBinaryRead as FileBinaryRead
from typer.models import FileBinaryWrite as FileBinaryWrite
from typer.models import FileText as FileText
from typer.models import FileTextWrite as FileTextWrite
from typer.params import Argument as Argument
from typer.params import Option as Option


__all__: list[str] = [
    'get_terminal_size',
    'Abort',
    'BadParameter',
    'Exit',
    'clear',
    'confirm',
    'echo_via_pager',
    'edit',
    'getchar',
    'pause',
    'progressbar',
    'prompt',
    'secho',
    'style',
    'unstyle',
    'echo',
    'format_filename',
    'get_app_dir',
    'get_binary_stream',
    'get_text_stream',
    'open_file',
    'colors',
    'Typer',
    'launch',
    'run',
    'CallbackParam',
    'Context',
    'FileBinaryRead',
    'FileBinaryWrite',
    'FileText',
    'FileTextWrite',
    'Argument',
    'Option',
]


# TODO: This is a copy of an internal variable in
# typer.main
_typer_developer_exception_attr_name = "__typer_developer_exception__"


class AsyncTyper(Typer):
    event_handlers: defaultdict[str, list[Callable[..., Any]]] = defaultdict(list)

    def async_command(self, *args: Any, **kwargs: Any):
        def decorator(async_func: Callable[..., Any]):
            async def main(*_args: Any, **_kwargs: Any) -> Any:
                await self.run_event_handlers("startup")
                try:
                    return await async_func(*_args, **_kwargs)
                except Exception as e:  # noqa
                    raise e
                finally:
                    await self.run_event_handlers("shutdown")

            @wraps(async_func)
            def f(*args: Any, **kwargs: Any) -> Any:
                return asyncio.run(main(*args, **kwargs))

            self.command(*args, **kwargs)(f)
            return async_func

        return decorator

    def add_event_handler(
        self,
        event_type: Literal['startup', 'shutdown'],
        func: Callable[..., Any]
    ) -> None:
        self.event_handlers[event_type].append(func)

    async def run_event_handlers(self, event_type: str):
        for event in self.event_handlers[event_type]:
            if asyncio.iscoroutinefunction(event):
                await event()
            else:
                event()