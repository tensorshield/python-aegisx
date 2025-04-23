import os

import yaml
from aegisx.core.const import AEGIS_USER_DIR

from aegisx.ext.oauth.models import ClientConfiguration


AEGISX_CLIENT_DIR = AEGIS_USER_DIR.joinpath('clients.d')


class LocalClientRepository:
    clients_dir = AEGISX_CLIENT_DIR

    def __init__(self):
        if not self.clients_dir.exists():
            os.makedirs(self.clients_dir)

    async def get(self, name: str) -> ClientConfiguration | None:
        filename = self.clients_dir.joinpath(f'{name}.yaml')
        if not filename.exists():
            return None
        with open(filename) as f:
            data = yaml.safe_load(f.read())
        return ClientConfiguration.model_validate(data)