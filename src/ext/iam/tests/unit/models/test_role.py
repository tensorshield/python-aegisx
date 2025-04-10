import pytest

from aegisx.ext.iam.models import Role
from aegisx.ext.iam.types import Permission


PREDEFINED_ROLES: list[tuple[str, set[Permission]]] = [
    ('roles/owner', {
        Permission('service.resource.create'),
        Permission('service.resource.delete'),
        Permission('service.resource.destroy'),
        Permission('service.resource.get'),
        Permission('service.resource.list'),
        Permission('service.resource.patch'),
        Permission('service.resource.replace'),
        Permission('service.resource.undelete'),
    }),
    ('roles/editor', {
        Permission('service.resource.create'),
        Permission('service.resource.get'),
        Permission('service.resource.list'),
        Permission('service.resource.patch'),
    }),
    ('roles/viewer', {
        Permission('service.resource.get'),
        Permission('service.resource.list'),
    }),
]


@pytest.mark.parametrize("name,permissions", PREDEFINED_ROLES)
def test_roles_exist(
    name: str,
    permissions: set[Permission],
    rolemap: dict[str, Role]
):
    assert rolemap.get(name)


@pytest.mark.parametrize("name,permissions", PREDEFINED_ROLES)
def test_roles_have_permissions(
    name: str,
    permissions: set[Permission],
    rolemap: dict[str, Role],
):
    role = rolemap.get(name)
    assert role is not None
    assert role.included_permissions == permissions