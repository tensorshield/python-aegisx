import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType
from .conftest import INPUT_FORMATS


INPUT_TYP: set[str] = {
    'octet-stream', 'image/png'
}


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
@pytest.mark.parametrize("cty", INPUT_TYP)
async def test_cty_is_interpreted_with_qualname(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
    cty: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!', cty=cty)\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    obj = adapter.validate_python(token)
    for signature in obj.get_signatures():
        if '/' not in cty:
            cty = f'application/{str.lower(cty)}'
        assert signature.cty == cty
