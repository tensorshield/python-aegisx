import importlib.metadata

from typer import Typer


app = Typer()


def main():
    entry_points = importlib.metadata.entry_points(group='aegisx.cli')
    for ep in entry_points:
        func = ep.load()
        func(app)
    app()