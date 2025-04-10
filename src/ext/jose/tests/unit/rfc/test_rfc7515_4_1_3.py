import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose.types import InvalidSignature

from .conftest import JOSEType


INPUT_FORMATS = ['compact', 'flattened', 'general']


# The "jwk" (JSON Web Key) Header Parameter is the public key that
# corresponds to the key used to digitally sign the JWS.  This key is
# represented as a JSON Web Key [JWK].  Use of this Header Parameter is
# OPTIONAL.
@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jws_with_evil_jwk_is_rejected(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    sig_evil: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    assert sig_evil.public
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jwk=sig_evil.public.model_dump())\
        .build(syntax=format, mode='python')
    with pytest.raises(InvalidSignature):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jws_with_valid_jwk_is_accepted(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, include=True)\
        .build(syntax=format, mode='python')
    adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jws_with_symmetric_jwk_is_rejected(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    sig_sym: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jwk=sig_sym.model_dump())\
        .build(syntax=format, mode='python')
    with pytest.raises(InvalidSignature):
        adapter.validate_python(token)


@pytest.mark.parametrize("format", INPUT_FORMATS)
@pytest.mark.asyncio
async def test_jws_with_private_jwk_is_rejected(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    format: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, jwk=sig.model_dump())\
        .build(syntax=format, mode='python')
    with pytest.raises(InvalidSignature):
        adapter.validate_python(token)