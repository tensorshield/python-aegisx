import datetime

import pytest
from aegisx.ext.jose.models import JSONWebKey

from aegisx.ext.iam.models import IAMAttachedPolicy
from aegisx.ext.iam.repository import IAMRepository
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal


@pytest.mark.asyncio
async def test_attach_policy(
    repo: IAMRepository,
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    policy = IAMAttachedPolicy.model_validate({
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
    await repo.persist(policy)
    policies = await repo.attached(['books/1'])
    assert len(policies) == 1
    assert policies[0] == policy


def test_digest_is_equal_between_serializations(
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    p1 = IAMAttachedPolicy.model_validate({
        'service': 'test.tensorshield.ai',
        'principal': user,
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
    p2 = IAMAttachedPolicy.model_validate_json(p1.model_dump_json())
    assert p1.digest == p2.digest


def test_model_dump_mode_persist(
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    p1 = IAMAttachedPolicy.model_validate({
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
    data = p1.model_dump(mode='persist')
    assert isinstance(data['attached'], datetime.datetime)


def test_initial_state_is_unsigned(
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    p1 = IAMAttachedPolicy.model_validate({
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
    assert not p1.is_signed()


@pytest.mark.asyncio
async def test_policy_is_signed_after_sign(
    sig: JSONWebKey,
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal
):
    p1 = IAMAttachedPolicy.model_validate({
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
    assert not p1.is_signed()
    await p1.policy.sign(sig, 'test.tensorshield.ai', 'books/1', 'root@tensorshield.ai')
    assert p1.is_signed()