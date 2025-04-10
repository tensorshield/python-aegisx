import pydantic
import pytest
from aegisx.ext.jose import JSONWebKey

from aegisx.ext.iam.models import AuthorizationContext
from aegisx.ext.iam.models import Role
from aegisx.ext.iam.models import RoleDefinitionRequest
from aegisx.ext.iam.models import IAMPolicy
from aegisx.ext.iam.models import IAMAttachedPolicy
from aegisx.ext.iam.models import IAMBinding
from aegisx.ext.iam.repository import MemoryIAMRepository
from aegisx.ext.iam.types import Permission
from aegisx.ext.iam.types import PrincipalType
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal
from aegisx.ext.iam.types import WildcardPermission


adapter: pydantic.TypeAdapter[PrincipalType] = pydantic.TypeAdapter(PrincipalType)


@pytest.fixture(scope='function')
def attached(
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    return IAMAttachedPolicy.model_validate({
        'service': 'test.tensorshield.ai',
        'policy': {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [user]
                },
                {
                    'role': 'roles/editor',
                    'members': [service_account]
                },
            ],
        },
        'target': 'books/1'
    })


@pytest.fixture(scope='function')
def permissions():
    return {
        Permission('service.resource.create'),
        Permission('service.resource.delete'),
        Permission('service.resource.destroy'),
        Permission('service.resource.get'),
        Permission('service.resource.list'),
        Permission('service.resource.patch'),
        Permission('service.resource.replace'),
        Permission('service.resource.undelete'),
        Permission('service2.resource.create'),
    }


@pytest.fixture(scope='function')
def policy():
    return IAMPolicy(
        bindings=tuple([
            IAMBinding[AuthorizationContext, PrincipalType](
                role='roles/owner',
                members=tuple([
                    adapter.validate_python('user:root@test.tensorshield.ai'),
                    adapter.validate_python('serviceAccount:root@test.tensorshield.ai'),
                ])
            ),
            IAMBinding(
                role='roles/everyone',
                members=tuple([
                    adapter.validate_python('allUsers'),
                ])
            ),
            IAMBinding(
                role='roles/authenticated',
                members=tuple([
                    adapter.validate_python('allAuthenticatedUsers'),
                ])
            ),
            IAMBinding(
                role='roles/group',
                members=tuple([
                    adapter.validate_python('group:group1@test.tensorshield.ai'),
                ])
            ),
            IAMBinding(
                role='roles/domain',
                members=tuple([
                    adapter.validate_python('domain:test.tensorshield.ai'),
                ])
            ),
        ])
    )


@pytest.fixture(scope='function')
def role_definitions():
    return [
        RoleDefinitionRequest.model_validate({
            'role_id': 'owner',
            'role': {
                'title': 'Owner',
                'included_permissions': {
                    WildcardPermission('service.**')
                }
            }
        }),
        RoleDefinitionRequest.model_validate({
            'role_id': 'editor',
            'role': {
                'title': 'Editor',
                'included_permissions': {
                    Permission('service.resource.create'),
                    Permission('service.resource.get'),
                    Permission('service.resource.list'),
                    Permission('service.resource.patch'),
                }
            }
        }),
        RoleDefinitionRequest.model_validate({
            'role_id': 'viewer',
            'role': {
                'title': 'Viewer',
                'included_permissions': {
                    Permission('service.resource.get'),
                    Permission('service.resource.list'),
                }
            }
        }),
    ]


@pytest.fixture(scope='function')
def roles(
    role_definitions: list[RoleDefinitionRequest],
    permissions: set[Permission]
):
    ctx: dict[str, set[Permission] | str] = {
        'permissions': permissions,
        'prefix': 'roles',
    }
    return [
        Role.model_validate(request, context=ctx)
        for request in role_definitions
    ]


@pytest.fixture(scope='function')
def rolemap(roles: list[Role]):
    return {role.name: role for role in roles}


@pytest.fixture(scope='function')
def repo():
    repo = MemoryIAMRepository()
    yield repo


@pytest.fixture
def service_account():
    return ServiceAccountPrincipal.validate('serviceAccount:app@test.tensorshield.ai')


@pytest.fixture(scope='session')
def sig():
    return JSONWebKey.generate(alg='ES256')


@pytest.fixture(scope='session')
def sig_evil():
    return JSONWebKey.generate(alg='ES256')


@pytest.fixture
def user():
    return UserPrincipal.validate('user:root@test.tensorshield.ai')