import pytest

from aegisx.ext.iam.models import Role
from aegisx.ext.iam.repository import IAMRoleRepository
from aegisx.ext.iam.repository import IAMRoleStaticRepository


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["roles/viewer", "roles/editor", "roles/owner"])
async def test_get(roles_repo: IAMRoleRepository, name: str):
    role = await roles_repo.get(name)
    assert role is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "names,expected", [
    (["roles/viewer", "roles/editor", "roles/owner"], 3),
    (["roles/viewer", "roles/editor", "roles/doesnotexist"], 2),
])
async def test_list(roles_repo: IAMRoleRepository, names: list[str], expected: int):
    roles = await roles_repo.filter(names)
    assert len(roles) == expected


@pytest.mark.asyncio
async def test_permission_inheritance(roles_repo: IAMRoleRepository):
    owner = await roles_repo.get('roles/owner')
    editor = await roles_repo.get('roles/editor')
    viewer = await roles_repo.get('roles/viewer')
    assert owner and editor and viewer
    assert owner.included_permissions >= (editor.included_permissions | viewer.included_permissions)
    assert editor.included_permissions >= viewer.included_permissions


@pytest.mark.parametrize(
    "roles", [
        (
            Role(name='foo', title="Foo", inherited_roles={'bar'}),
            Role(name='bar', title="Bar", inherited_roles={'foo'})
        ),
        (
            Role(name='foo', title="Foo", inherited_roles={'bar'}),
            Role(name='bar', title="Bar", inherited_roles={'baz'}),
            Role(name='baz', title="Baz", inherited_roles={'foo'})
        ),
        (
            Role(name='foo', title='Foo', inherited_roles={'bar', 'baz'}),
            Role(name='bar', title="Bar", inherited_roles={'qux'}),
            Role(name='baz', title="Baz", inherited_roles={'qux'}),
            Role(name='qux', title='Qux', inherited_roles={'foo'})
        ),
        (
            Role(name='foo', title='Foo', inherited_roles={'bar', 'baz'}),
            Role(name='bar', title="Bar", inherited_roles={'qux'}),
            Role(name='baz', title="Baz", inherited_roles={'qux'}),
            Role(name='qux', title='Qux', inherited_roles={'bar'})
        ),
        (
            Role(name='foo', title='Foo', inherited_roles={'bar', 'baz'}),
            Role(name='bar', title="Bar", inherited_roles={'qux'}),
            Role(name='baz', title="Baz"),
            Role(name='qux', title='Qux', inherited_roles={'bar'})
        ),
        (
            Role(name='foo', title='Foo', inherited_roles={'bar', 'baz', 'taz'}),
            Role(name='bar', title="Bar", inherited_roles={'qux', 'taz'}),
            Role(name='baz', title="Baz"),
            Role(name='qux', title='Qux', inherited_roles={'bar'})
        ),
    ]
)
def test_infinite_recursion_raises_error(
    roles: list[Role],
):
    with pytest.raises(TypeError):
        IAMRoleStaticRepository(roles=roles)


@pytest.mark.asyncio
async def test_permissions(roles_repo: IAMRoleRepository):
    owner = await roles_repo.get('roles/owner')
    editor = await roles_repo.get('roles/editor')
    viewer = await roles_repo.get('roles/viewer')
    assert owner and editor and viewer
    assert await roles_repo.permissions(['roles/owner']) == owner.included_permissions