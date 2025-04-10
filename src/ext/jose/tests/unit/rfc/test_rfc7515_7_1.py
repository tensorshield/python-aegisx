import pydantic
import pytest
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import JSONWebToken
from .conftest import JOSEType


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_payload_is_base64_encoded_bytes(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    assert b64decode(token['payload']) == b'Hello world!'


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_payload_is_base64_encoded_jwt(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(JSONWebToken)\
        .sign(sig, alg='ES256')\
        .update({'iss': 'foo@bar.baz'})\
        .build(syntax=syntax, mode='python')
    assert b64decode(token['payload']) == b'{"iss":"foo@bar.baz"}'
