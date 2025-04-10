import pytest
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.rfc3161 import TimestampClient
from aegisx.ext.rfc3161 import TimestampAuthority

from aegisx.ext.iam.models import IAMAttachedPolicy
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal


@pytest.mark.asyncio
async def test_stamp_policy(
    service_account: ServiceAccountPrincipal,
    user: UserPrincipal,
    sig: JSONWebKey
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
    client = TimestampClient(
        using={
            TimestampAuthority.APPLE,
            TimestampAuthority.MICROSOFT,
            TimestampAuthority.SWISSSIGN,
            TimestampAuthority.ZEITSTEMPEL,
        }
    )
    await policy.policy.sign(
        sig,
        'test.tensorshield.ai',
        'books/1',
        'root@tensorshield.ai'
    )
    async with client:
        await policy.stamp(client)
    assert policy.timestamps