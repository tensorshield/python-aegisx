import pytest

from aegisx.ext.oauth.models import ServerMetadata


AUTHORIZATION_SERVERS: set[str] = {
    'https://accounts.google.com',
    'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0'
}


@pytest.mark.parametrize("issuer", AUTHORIZATION_SERVERS)
@pytest.mark.asyncio
async def test_discovery(issuer: str):
    metadata = ServerMetadata(issuer=issuer)
    assert await metadata.discover()
    assert not await metadata.discover()
    assert metadata.is_discovered()