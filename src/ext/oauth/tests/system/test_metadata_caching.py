import pytest

from aegisx.ext.oauth import ServerMetadata


@pytest.mark.asyncio
@pytest.mark.parametrize("issuer", ["https://accounts.google.com"])
async def test_metadata_is_cached(issuer: str):
    ServerMetadata.clear()
    assert not ServerMetadata.is_cached(issuer)
    await ServerMetadata.get(issuer)
    assert ServerMetadata.is_cached(issuer)