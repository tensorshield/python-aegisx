import pydantic
import pytest

from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
@pytest.mark.parametrize("value", [
    '{"tag":"value"}ABCD'
])
async def test_malformed_json_is_rejected(
    value: str,
    adapter: pydantic.TypeAdapter[JOSEType],
    syntax: TokenBuilder.SerializationFormat,
):
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(value)