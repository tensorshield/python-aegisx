import base64
import hashlib

import pydantic
import pytest
from cryptography.x509 import Certificate

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType
from .conftest import INPUT_FORMATS


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_matching_x5t_s256_is_accepted(
    adapter: pydantic.TypeAdapter[JOSEType],
    syntax: TokenBuilder.SerializationFormat,
    x5c_valid_chain: tuple[Certificate, JSONWebKey, list[str]]
):
    _, key, chain = x5c_valid_chain
    t = base64.urlsafe_b64encode(
        hashlib.sha256(base64.urlsafe_b64decode(chain[0])).digest()
    )
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(key, alg='ES256', x5c=chain, x5t_sha256=t.decode('ascii'))\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_mismatching_x5t_s256_is_rejected(
    adapter: pydantic.TypeAdapter[JOSEType],
    syntax: TokenBuilder.SerializationFormat,
    x5c_valid_chain: tuple[Certificate, JSONWebKey, list[str]]
):
    _, key, chain = x5c_valid_chain
    t = base64.urlsafe_b64encode(
        hashlib.sha256(base64.urlsafe_b64decode(chain[0])).digest() + b'0'
    )
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(key, alg='ES256', x5c=chain, x5t_sha256=t.decode('ascii'))\
        .build(syntax=syntax, mode='python')
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)