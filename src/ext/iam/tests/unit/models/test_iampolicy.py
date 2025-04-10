import pytest
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose.types import ForbiddenAudience

from aegisx.ext.iam.models import AuthorizationContext
from aegisx.ext.iam.models import IAMPolicy


def test_policy_has_roles(policy: IAMPolicy):
    assert policy.roles == {
        'roles/owner',
        'roles/authenticated',
        'roles/everyone',
        'roles/group',
        'roles/domain'
    }


@pytest.mark.parametrize("roles,ctx", [
    (
        {'roles/owner', 'roles/authenticated', 'roles/everyone', 'roles/domain'},
        AuthorizationContext.model_validate({
            'principal': 'user:root@test.tensorshield.ai',
            'subject': {
                'email': 'root@test.tensorshield.ai',
                'service_account': False
            }
        })
    ),
    (
        {'roles/owner', 'roles/authenticated', 'roles/everyone', 'roles/domain', 'roles/group'},
        AuthorizationContext.model_validate({
            'principal': 'user:root@test.tensorshield.ai',
            'subject': {
                'email': 'root@test.tensorshield.ai',
                'service_account': False,
                'groups': {'group1@test.tensorshield.ai'}
            }
        })
    ),
    (
        {'roles/owner', 'roles/authenticated', 'roles/everyone', 'roles/domain'},
        AuthorizationContext.model_validate({
            'principal': 'serviceAccount:root@test.tensorshield.ai',
            'subject': {
                'email': 'root@test.tensorshield.ai',
                'service_account': True
            }
        })
    ),
    (
        {'roles/everyone'},
        AuthorizationContext.model_validate({
            'principal': 'allUsers'
        })
    ),
    (
        {'roles/authenticated', 'roles/everyone'},
        AuthorizationContext.model_validate({
            'principal': 'allAuthenticatedUsers'
        })
    ),
])
def test_granted_roles_from_policy(
    policy: IAMPolicy,
    ctx: AuthorizationContext,
    roles: set[str]
):
    assert policy.granted(ctx) == roles


def test_root_policy():
    policy = IAMPolicy.root(['serviceAccount:root@test.tensorshield.ai'], role='roles/root')
    ctx = AuthorizationContext.model_validate({
        'principal': 'serviceAccount:root@test.tensorshield.ai'
    })
    assert policy.granted(ctx) == {'roles/root'}


def test_condition_invalid(policy: IAMPolicy):
    ctx = AuthorizationContext.model_validate({
        'principal': 'serviceAccount:root@test.tensorshield.ai',
        'remote_host': '8.8.8.8'
    })
    binding = policy.bindings[0]
    binding.add_condition(
        title="Allow 4.4.4.4",
        expression='ctx.remote_host == "4.4.4.4"'
    )

    assert ctx.principal in binding.members
    assert policy.granted(ctx) ^ {"roles/owner"}


def test_condition_valid():
    policy = IAMPolicy.model_validate({
        'bindings': [
            {
                'role': 'roles/owner',
                'members': {'serviceAccount:root@test.tensorshield.ai'},
                'condition': {
                    'title': 'Allow 4.4.4.4',
                    'description': 'Test condition',
                    'expression': 'ctx.remote_host == "4.4.4.4"'
                }
            }
        ]
    })
    ctx = AuthorizationContext.model_validate({
        'principal': 'serviceAccount:root@test.tensorshield.ai',
        'remote_host': '8.8.8.8'
    })
    assert not policy.granted(ctx) & {"roles/owner"}

    ctx = AuthorizationContext.model_validate({
        'principal': 'serviceAccount:root@test.tensorshield.ai',
        'remote_host': '4.4.4.4'
    })
    assert policy.granted(ctx) & {"roles/owner"}


def test_digest(policy: IAMPolicy):
    p2 = IAMPolicy.model_validate_json(policy.model_dump_json())
    assert policy.digest == p2.digest


@pytest.mark.asyncio
async def test_sign_and_verify_self(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    assert await policy.verify(
        [sig],
        'test.tensorshield.ai',
        'books/1',
        'root@tensorshield.ai'
    )


@pytest.mark.asyncio
async def test_sign_and_verify_mismatch_service(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    with pytest.raises(ForbiddenAudience):
        assert not await policy.verify(
            [sig],
            'other.tensorshield.ai',
            'books/1',
            'root@tensorshield.ai'
        )


@pytest.mark.asyncio
async def test_sign_and_verify_evil(
    sig: JSONWebKey,
    sig_evil: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig_evil, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    assert not await policy.verify(
        [sig],
        'test.tensorshield.ai',
        'books/1',
        'root@tensorshield.ai'
    )



@pytest.mark.asyncio
async def test_verify_unsigned_is_false(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    assert not await policy.verify([sig], 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')


@pytest.mark.asyncio
async def test_sign_and_verify_reconstructed(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    reconstructed = IAMPolicy.model_validate_json(policy.model_dump_json())
    assert await reconstructed.verify([sig], 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')


@pytest.mark.asyncio
async def test_sign_and_verify_tampered_payload(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    reconstructed = IAMPolicy.model_validate({
        **policy.model_dump(),
        'bindings': [
            {
                'role': 'roles/owner',
                'members': [
                    'user:evil@tensorshield.ai'
                ]
            }
        ]
    })
    assert not await reconstructed.verify([sig], 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')


@pytest.mark.asyncio
async def test_issuer_is_principal(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    assert policy.principal == 'root@tensorshield.ai'


@pytest.mark.asyncio
async def test_initial_state_is_unsigned(
    policy: IAMPolicy
):
    assert not policy.is_signed()


@pytest.mark.asyncio
async def test_policy_is_signed(
    sig: JSONWebKey,
    policy: IAMPolicy
):
    assert not policy.is_signed()
    await policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    assert policy.is_signed()