import httpx
import pytest

from aegisx.ext.google.auth import GoogleServiceAccountAuth
from .conftest import HTTP_METHODS
from .conftest import UserInfoResponse


@pytest.mark.asyncio
@pytest.mark.parametrize("method", HTTP_METHODS)
async def test_authenticated_request_subject(
    client: httpx.AsyncClient,
    method: str,
    default_auth: GoogleServiceAccountAuth
):
    response = await client.request(method=method, url='/', auth=default_auth)
    try:
        result = UserInfoResponse.model_validate(response.json())
    except ValueError:
        pytest.fail(response.text)
    assert result.subject is not None
    assert result.subject.is_authenticated()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", HTTP_METHODS)
async def test_invalid_audience_returns_403(
    client: httpx.AsyncClient,
    default_auth: GoogleServiceAccountAuth,
    method: str
):
    auth = default_auth.with_audience('https://example.invalid')
    response = await client.request(method=method, url='/', auth=auth)
    assert response.status_code == 403