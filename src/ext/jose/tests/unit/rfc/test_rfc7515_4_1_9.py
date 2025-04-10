import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType
from .conftest import INPUT_FORMATS


INPUT_TYP: set[str] = {
    'JWT', 'jwt', 'JOSE', 'application/jose',
    'at+jwt'
}


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
@pytest.mark.parametrize("typ", INPUT_TYP)
async def test_typ_is_interpreted_with_qualname(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
    typ: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256', typ=typ)\
        .build(syntax=syntax, mode='python')
    obj = adapter.validate_python(token)
    for signature in obj.get_signatures():
        if '/' not in typ:
            typ = f'application/{str.lower(typ)}'
        assert signature.typ == typ
