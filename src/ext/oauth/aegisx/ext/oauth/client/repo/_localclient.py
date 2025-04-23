import os
import stat

import yaml
from aegisx.core.const import AEGIS_USER_DIR

from aegisx.ext.oauth.models import ClientConfiguration
from aegisx.ext.oauth.models import TokenResponse
from ._base import ClientRepository


AEGISX_CLIENT_DIR = AEGIS_USER_DIR.joinpath('clients.d')

AEGISX_GRANTS_DIR = AEGIS_USER_DIR.joinpath('grants.d')


class LocalClientRepository(ClientRepository):
    clients_dir = AEGISX_CLIENT_DIR
    grants_dir = AEGISX_GRANTS_DIR

    def __init__(self):
        if not self.clients_dir.exists():
            os.makedirs(self.clients_dir)
        if not self.grants_dir.exists():
            os.makedirs(self.grants_dir)

    async def get(self, name: str) -> ClientConfiguration | None:
        filename = self.clients_dir.joinpath(f'{name}.yaml')
        if not filename.exists():
            return None
        with open(filename) as f:
            data = yaml.safe_load(f.read())
        return ClientConfiguration.model_validate(data)

    async def grant(self, client_id: str) -> TokenResponse | None:
        filename = self.grants_dir.joinpath(f'{client_id}')
        if not filename.exists():
            return None
        with open(filename, 'r') as f:
            return TokenResponse.model_validate_json(f.read())

    async def persist_grant(
        self,
        obj: TokenResponse,
        config: ClientConfiguration
    ) -> None:
        filename = self.grants_dir.joinpath(f'{config.client_id}')
        with open(filename, 'w') as f:
            f.write(obj.model_dump_json(exclude_none=True))
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)