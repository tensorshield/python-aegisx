import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebKeySet
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose import JSONWebToken


class TypedJWT1(JSONWebToken):
    foo: str


class TypedJWT2(JSONWebToken):
    bar: str


@pytest.mark.asyncio
async def test_token_builder_simple(sig: JSONWebKey):
    validator = TokenValidator(TypedJWT1, jwks=JSONWebKeySet(keys=[sig]))
    jws = await TokenBuilder(TypedJWT1)\
        .update(foo='Hello world!')\
        .sign(sig)\
        .build()
    jwt = await validator.validate(jws)
    assert jwt.foo == 'Hello world!'


@pytest.mark.asyncio
async def test_validator_requires_audience_intersection(sig: JSONWebKey):
    validator = TokenValidator(
        TypedJWT1,
        audience='https://jose.example',
        jwks=JSONWebKeySet(keys=[sig])
    )
    jws = await TokenBuilder(TypedJWT1)\
        .audience('https://x509.example')\
        .update(foo='Hello world!')\
        .sign(sig)\
        .build()
    with pytest.raises(pydantic.ValidationError):
        await validator.validate(jws)


@pytest.mark.asyncio
async def test_validator_rejects_missing_audience(sig: JSONWebKey):
    validator = TokenValidator(
        TypedJWT1,
        audience='https://jose.example',
        jwks=JSONWebKeySet(keys=[sig])
    )
    jws = await TokenBuilder(TypedJWT1)\
        .update(foo='Hello world!')\
        .sign(sig)\
        .build()
    with pytest.raises(pydantic.ValidationError):
        await validator.validate(jws)


@pytest.mark.asyncio
async def test_validator_requires_equal_issuer(sig: JSONWebKey):
    validator = TokenValidator(
        TypedJWT1,
        issuer='https://jose.example',
        jwks=JSONWebKeySet(keys=[sig])
    )
    jws = await TokenBuilder(TypedJWT1)\
        .issuer('https://x509.example')\
        .update(foo='Hello world!')\
        .sign(sig)\
        .build()
    with pytest.raises(pydantic.ValidationError):
        await validator.validate(jws)


@pytest.mark.asyncio
async def test_validator_rejects_missing_issuer(sig: JSONWebKey):
    validator = TokenValidator(
        TypedJWT1,
        issuer='https://jose.example',
        jwks=JSONWebKeySet(keys=[sig])
    )
    jws = await TokenBuilder(TypedJWT1)\
        .update(foo='Hello world!')\
        .sign(sig)\
        .build()
    with pytest.raises(pydantic.ValidationError):
        await validator.validate(jws)