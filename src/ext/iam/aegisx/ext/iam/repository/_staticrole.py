import pathlib
import itertools
from typing import cast
from typing import Any
from typing import Generic
from typing import Iterable
from typing import TypeVar

import pydantic
import yaml

from aegisx.ext.iam.models import Role
from aegisx.ext.iam.types import Permission
from aegisx.ext.iam.types import WildcardPermission
from ._baserole import IAMRoleRepository


R = TypeVar('R', bound=Role, default=Role)


class IAMRoleStaticRepository(IAMRoleRepository[R], Generic[R]):
    _roles: dict[str, R]

    def __init__(
        self,
        config_dir: pathlib.Path | str | None = None,
        roles: Iterable[R] | None = None,
        model: type[R] = Role
    ):
        self._roles = {}
        if config_dir and not isinstance(config_dir, pathlib.Path):  # pragma: no cover
            assert isinstance(config_dir, str)
            config_dir = pathlib.Path(config_dir)
        self.config_dir = config_dir

        if self.config_dir is not None:
            assert isinstance(self.config_dir, pathlib.Path)
            failed: list[tuple[pathlib.Path, dict[str, Any]]] = []
            for filename in self.config_dir.glob('*.yaml'):
                if not filename.is_file(): # pragma: no cover
                    continue
                data: Any = yaml.safe_load(open(filename).read())
                if not isinstance(data, list): # pragma: no cover
                    raise TypeError(f'Invalid role specification in {filename}')
                for spec in cast(list[dict[str, Any]], data):
                    try:
                        role = model.model_validate(spec)
                    except pydantic.ValidationError:  # pragma: no cover
                        failed.append((filename, spec))
                        continue
                    self._roles[role.name] = role

            if failed: # pragma: no cover
                raise TypeError(
                    f'Failed parsing {len(failed)} roles from '
                    f'config directory {config_dir}'
                )

        for role in (roles or []):
            self._roles[role.name] = role

        self._update_inherited_permissions()

    async def get(self, name: str) -> R | None:
        return self._roles.get(name)

    async def filter(self, names: Iterable[str]) -> list[R]:
        return [self._roles[n] for n in names if n in self._roles]

    async def permissions(
        self,
        names: Iterable[str]
    ) -> set[Permission | WildcardPermission]:
        return set(
            itertools.chain(*[
                role.included_permissions
                for role in await self.filter(names)
            ])
        )

    def _get_inherited_permissions(
        self,
        parents: set[str],
        seen: set[str]
    ) -> set[Permission | WildcardPermission]:
        permissions: set[Permission | WildcardPermission] = set()
        for name in parents:
            role = self._roles.get(name)
            if role is None:
                continue
            if name in seen:
                raise TypeError('Infinite recursion in inheritance tree.')
            seen.add(name)
            permissions.update(role.included_permissions)
            if role.inherited_roles:
                permissions.update(self._get_inherited_permissions(role.inherited_roles, seen))
        return permissions

    def _update_inherited_permissions(self):
        for role in self._roles.values():
            if not role.inherited_roles:
                continue
            role.included_permissions.update(
                self._get_inherited_permissions(role.inherited_roles, set())
            )