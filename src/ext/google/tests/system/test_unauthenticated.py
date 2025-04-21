import httpx
import pytest

from .conftest import HTTP_METHODS
from .conftest import UserInfoResponse


@pytest.mark.asyncio
@pytest.mark.parametrize("method", HTTP_METHODS)
async def test_unauthenticated_request_has_no_subject(
    client: httpx.AsyncClient,
    method: str
):
    response = await client.request(method=method, url='/')
    try:
        result = UserInfoResponse.model_validate(response.json())
    except ValueError:
        pytest.fail(response.text)
    assert result.subject is not None
    assert not result.subject.is_authenticated()