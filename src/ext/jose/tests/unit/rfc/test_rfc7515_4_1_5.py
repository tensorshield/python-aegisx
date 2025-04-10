import pydantic
import pytest
from libcanonical.types import DomainName
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder

from .conftest import JOSEType


INPUT_FORMATS = ['compact', 'flattened', 'general']

INPUT_URL = ["https://x509.example", "https://x509.example/foo/x509.pem", 'https://x509.example/x509.pem']

X5U_WHITELIST: set[DomainName | HTTPResourceLocator] = {
    DomainName('x509.example'),
    HTTPResourceLocator('https://x509.example/foo')
}

# The protocol used to acquire the resource
# MUST provide integrity protection; an HTTP GET request to retrieve
# the certificate MUST use TLS [RFC2818] [RFC5246];
@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_x5u_requires_tls(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, x5u='http://x509.invalid')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_x5u_requires_tls_whitelist(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, x5u='http://x509.example')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token, context={'x5u': X5U_WHITELIST})

# and the identity of the server MUST be validated,
# as per Section 6 of RFC 6125 [RFC6125].
@pytest.mark.parametrize("url", INPUT_URL)
@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_x5u_must_be_whitelisted(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
    url: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, x5u=url)\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_x5u_must_be_subpath(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, x5u='https://x509.example/foo/qux/x509.pem')\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(
            token,
            context={'x5u': {HTTPResourceLocator('https://x509.example/foo/bar/x509.pem')}}
        )


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.parametrize("url", INPUT_URL)
@pytest.mark.asyncio
async def test_x5u_is_accepted_if_whitelisted(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
    url: str
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, x5u=url)\
        .build(syntax=format, mode='python')
    assert isinstance(token, dict)
    adapter.validate_python(token, context={'x5u': X5U_WHITELIST})