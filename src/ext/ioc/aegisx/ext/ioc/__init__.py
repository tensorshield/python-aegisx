from dependency_injector.wiring import inject
from dependency_injector.wiring import Provide
from dependency_injector import providers
from dependency_injector import resources

from . import fastapi
from .containers import Container
from .containers import DeclarativeContainer


__all__: list[str] = [
    'inject',
    'fastapi',
    'providers',
    'resources',
    'Container',
    'DeclarativeContainer',
    'Provide'
]