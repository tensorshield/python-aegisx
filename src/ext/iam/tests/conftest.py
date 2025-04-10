from typing import Literal

import pytest
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.rfc3161 import TimestampToken

from aegisx.ext.iam.repository import MemoryIAMRepository
from aegisx.ext.iam.types import ServiceAccountPrincipal
from aegisx.ext.iam.types import UserPrincipal


@pytest.fixture
def repo():
    return MemoryIAMRepository()


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


@pytest.fixture
def timestamper():
    return MockTimestampClient()


class MockTimestampClient:

    async def timestamps(
        self,
        data: bytes,
        algorithm: Literal['sha1', 'sha256', 'sha384', 'sha512'] = 'sha256',
        timeout: int = 60
    ) -> list[TimestampToken]:
        return []