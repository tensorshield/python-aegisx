import pytest
from libcanonical.utils.encoding import b64encode

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.types import JWSCompactEncoded
from aegisx.ext.jose.types import MalformedPayload


INVALID_JWT_BODIES: list[str] = [
    b64encode('{', encoder=str),  # Decodes to: { (Incomplete JSON object)
    b64encode('{}..', encoder=str),  # Decodes to: {}.. (Invalid JSON, trailing dots)
    b64encode('..{}', encoder=str),  # Decodes to: ..{} (Invalid JSON, leading dots)
    b64encode('{"foo: "bar"}', encoder=str),  # Decodes to: {"foo: "bar"} (Missing closing quote for key)
    b64encode('{"foo: "bar}', encoder=str),  # Decodes to: {"foo: "bar} (Missing closing quote for key)
    b64encode('{foo: "bar}', encoder=str),  # Decodes to: {foo: "bar} (Unquoted key)
    b64encode('{"foo": "bar"', encoder=str),  # Decodes to: {"foo": "bar" (Missing closing brace)
    b64encode('[]', encoder=str),  # Decodes to: [] (Valid empty array, but in context it might be invalid)
    b64encode('Hello world!', encoder=str),  # Decodes to: Hello world! (Not valid JSON at all)
    b64encode('{}-', encoder=str),  # Decodes to: {}- (Invalid JSON, trailing character after closing brace)
    b64encode('{"foo":}', encoder=str),  # Decodes to: {"foo":} (Missing value after colon)
    b64encode('{"foo": "bar",}', encoder=str),  # Decodes to: {"foo": "bar",} (Trailing comma)
    b64encode('{"foo": "bar" "baz": "qux"}', encoder=str),  # Decodes to: {"foo": "bar" "baz": "qux"} (Missing comma)
    b64encode('{"foo" "bar": "baz"}', encoder=str),  # Decodes to: {"foo" "bar": "baz"} (Missing colon)
    b64encode('{"foo" "bar"}', encoder=str),  # Decodes to: {"foo" "bar"} (Missing colon)
    b64encode('{"foo": "bar", "baz" 1}', encoder=str),  # Decodes to: {"foo": "bar", "baz" 1} (Invalid number format)
    b64encode('{"foo": "bar", 12345}', encoder=str),  # Decodes to: {"foo": "bar", 12345} (Invalid key type, no quotes)
    b64encode('{"foo": "bar", }', encoder=str),  # Decodes to: {"foo": "bar", } (Trailing comma)
    b64encode('{"foo": true}', encoder=str),  # Decodes to: {"foo": true} (Valid JSON, but only one key-value pair)
    b64encode('{"foo": "bar"', encoder=str),  # Decodes to: {"foo": "bar" (Missing closing brace)
    b64encode('{"foo": "bar" "baz": "qux"}', encoder=str),  # Decodes to: {"foo": "bar" "baz": "qux"} (Missing comma)
    b64encode('{foo: "bar"}', encoder=str),  # Decodes to: {foo: "bar"} (Unquoted key)
    b64encode('{"foo": "bar", "baz": "qux" "quux": 1}', encoder=str),  # Decodes to: {"foo": "bar", "baz": "qux" "quux": 1} (Missing comma)
    b64encode('{"foo" : "bar" : "baz"}', encoder=str),  # Decodes to: {"foo" : "bar" : "baz"} (Multiple colons)
    b64encode('{"foo": "bar" "baz": 1}', encoder=str),  # Decodes to: {"foo": "bar" "baz": 1} (Missing comma)
    b64encode('{"foo": "bar" 1: "baz"}', encoder=str),  # Decodes to: {"foo": "bar" 1: "baz"} (Invalid key, no quotes)
    b64encode('{"foo": "bar", "baz": null', encoder=str),  # Decodes to: {"foo": "bar", "baz": null (Missing closing brace)
    b64encode('{"foo": "bar", "baz"="qux"}', encoder=str),  # Decodes to: {"foo": "bar", "baz"="qux"} (Invalid assignment)
    b64encode('{"foo": "bar", "baz": {}}', encoder=str),  # Decodes to: {"foo": "bar", "baz": {}} (Valid JSON but redundant empty object)
    b64encode('{"foo": "bar", "baz": [', encoder=str),  # Decodes to: {"foo": "bar", "baz": [ (Incomplete array)
    b64encode('{"foo": "bar", "baz": 1.5}', encoder=str),  # Decodes to: {"foo": "bar", "baz": 1.5} (Valid, but might be out of context)
    b64encode('{"foo": "bar", "baz": "qux",}', encoder=str),  # Decodes to: {"foo": "bar", "baz": "qux",} (Trailing comma)
    b64encode('{"foo": "bar" "baz"=true}', encoder=str),  # Decodes to: {"foo": "bar" "baz"=true} (Invalid syntax between fields)
    b64encode('{"foo": {"bar": "baz"}}', encoder=str),  # Decodes to: {"foo": {"bar": "baz"}} (Valid JSON but redundant structure)
]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", INVALID_JWT_BODIES)
async def test_valid_compact_jws_with_malformed_jwt(sig: JSONWebKey, value: str):
    t = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .sign(sig)\
        .build(syntax='flattened')
    e = JWSCompactEncoded.validate(t)
    e = e.with_payload(value)
    with pytest.raises(MalformedPayload):
        result = await TokenValidator(JSONWebToken, verify=False).validate(str(e))
        print(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", INVALID_JWT_BODIES)
async def test_valid_flattened_jws_with_malformed_jwt(sig: JSONWebKey, value: str):
    t = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .sign(sig)\
        .build(mode='python', syntax='flattened')
    assert isinstance(t, dict), repr(t)
    t['payload'] = value
    with pytest.raises(MalformedPayload):
        result = await TokenValidator(JSONWebToken, verify=False).validate(t)
        print(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", INVALID_JWT_BODIES)
async def test_valid_general_jws_with_malformed_jwt(
    sig: JSONWebKey,
    sig_evil: JSONWebKey,
    value: str
):
    t = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .sign(sig)\
        .sign(sig_evil)\
        .build(mode='python', syntax='general')
    assert isinstance(t, dict), repr(t)
    assert t.get('signatures'), repr(t)
    t['payload'] = value
    with pytest.raises(MalformedPayload):
        result = await TokenValidator(JSONWebToken, verify=False).validate(t)
        print(result)