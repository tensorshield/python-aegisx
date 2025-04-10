import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_payload_must_be_present(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)
    token.pop('payload')
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_signatures_must_be_present(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)
    token.pop('signatures')
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_signature_signature_must_be_present(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)
    token['signatures'][0].pop('signature')
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_signature_protected_or_header_must_be_present(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)
    token['signatures'][0].pop('header', None)
    token['signatures'][0].pop('protected', None)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)



@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", ['general'])
async def test_signature_protected_and_unprotected_header_must_be_disjoint(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256')\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)
    token['signatures'][0]['header'] = {'alg': 'ES256'}
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)