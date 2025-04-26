#!/usr/bin/env python3
import json
import os
import pathlib
from setuptools import find_namespace_packages
from setuptools import setup # type: ignore


SETUPDIR = pathlib.Path(__file__).parent

PKGDIR = SETUPDIR.joinpath('aegisx/ext/uvicorn')

packages = find_namespace_packages(
    where='.',
    include=["aegisx.*"],
    exclude={'build', 'dist', 'tests', 'var'}
)
opts = json.loads((open(f'{PKGDIR}/package.json').read()))
version = str.strip(open('VERSION').read())
if os.path.exists(os.path.join(SETUPDIR, 'README.md')):
    with open(os.path.join(SETUPDIR, 'README.md'), encoding='utf-8') as f:
        opts['long_description'] = f.read()
        opts['long_description_content_type'] = "text/markdown"

setup(
    version=version,
    packages=packages,
    include_package_data=True,
    **opts
)
