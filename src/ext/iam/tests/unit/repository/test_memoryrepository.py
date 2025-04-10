import pytest

from aegisx.ext.iam.models import Role
from aegisx.ext.iam.models import IAMAttachedPolicy
from aegisx.ext.iam.repository import IAMRepository
from aegisx.ext.iam.types import Permission


@pytest.mark.asyncio
async def test_persist_policy(
    repo: IAMRepository,
    attached: IAMAttachedPolicy
):
    await repo.persist(attached)
    assert await repo.attached([attached.target]) == [attached]


@pytest.mark.asyncio
async def test_persist_role(
    repo: IAMRepository,
):
    role = Role(
        name='roles/owner',
        title="Test",
        included_permissions={Permission("foo.bar.baz")}
    )
    await repo.persist(role)
    assert [x async for x in repo.roles(["roles/owner"])] == [role]


@pytest.mark.asyncio
async def test_get_role(
    repo: IAMRepository,
):
    role = Role(
        name='roles/owner',
        title="Test",
        included_permissions={Permission("foo.bar.baz")}
    )
    await repo.persist(role)
    assert await repo.role('roles/owner') == role


@pytest.mark.asyncio
async def test_get_permissions(
    repo: IAMRepository,
):
    role = Role(
        name='roles/owner',
        title="Test",
        included_permissions={Permission("foo.bar.baz")}
    )
    await repo.persist(role)
    assert await repo.permissions(["roles/owner"]) == role.included_permissions


@pytest.mark.asyncio
async def test_lookup_roles_ignores_non_existant(
    repo: IAMRepository,
):
    role = Role(
        name='roles/owner',
        title="Test",
        included_permissions={Permission("foo.bar.baz")}
    )
    await repo.persist(role)
    assert [x async for x in repo.roles(["roles/owner", "roles/doesnotexist"])] == [role]


@pytest.mark.asyncio
async def test_lookup_roles_limits(
    repo: IAMRepository,
):
    for i in range(2):
        role = Role(
            name=f'roles/owner{i}',
            title="Test",
            included_permissions={Permission("foo.bar.baz")}
        )
        await repo.persist(role)
    assert len([x async for x in repo.roles(["roles/owner0", "roles/owner1"], limit=1)])  == 1