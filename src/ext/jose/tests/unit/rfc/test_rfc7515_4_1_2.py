import pydantic
import pytest
from libcanonical.types import DomainName
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder

from .conftest import JOSEType


INPUT_FORMATS = ['compact', 'flattened', 'general']

INPUT_URL = ["https://jwks.example", "https://jwks.example/foo/jwks.json", 'https://jwks.example/jwks.json']

JKU_WHITELIST: set[DomainName | HTTPResourceLocator] = {
    DomainName('jwks.example'),
    HTTPResourceLocator('https://jwks.example/foo')
}

# The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
# refers to a resource for a set of JSON-encoded public keys, one of
# which corresponds to the key used to digitally sign the JWS.  The
# keys MUST be encoded as a JWK Set [JWK].  The protocol used to
# acquire the resource MUST provide integrity protection; an HTTP GET
# request to retrieve the JWK Set MUST use Transport Layer Security
# (TLS) [RFC2818] [RFC5246];
@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jku_requires_tls(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jku='http://jwks.invalid')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jku_requires_tls_whitelist(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jku='http://jwks.example')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token, context={'jku': JKU_WHITELIST})

# and the identity of the server MUST be
# validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
# Section 8 on TLS requirements.  Use of this Header Parameter is
# OPTIONAL.
@pytest.mark.parametrize("url", INPUT_URL)
@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jku_must_be_whitelisted(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
    url: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jku=url)\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jku_must_be_subpath(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jku='https://jwks.example/foo/qux/jwks.json')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(
            token,
            context={'jku': {HTTPResourceLocator('https://jwks.example/foo/bar/jwks.json')}}
        )


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.parametrize("url", INPUT_URL)
@pytest.mark.asyncio
async def test_jku_is_accepted_if_whitelisted(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
    url: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jku=url)\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    adapter.validate_python(token, context={'jku': JKU_WHITELIST})