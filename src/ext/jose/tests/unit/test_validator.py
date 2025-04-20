import pytest
import pydantic
import hashlib

from libcanonical.types import Base64URLEncoded

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import SerializationFormat
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.types import JWSCompactEncoded
from aegisx.ext.jose.types import JWECompactEncoded


class CustomTokenSchema(JSONWebToken):
    foo: str


SIGNERS: list[tuple[JSONWebKey, ...]] = [
    tuple(),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519'),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', kid='foo'),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519'),
        JSONWebKey.generate(alg='ES256'),
    ),
]

RECIPIENTS: list[tuple[JSONWebKey, ...]] = [
    tuple(),
    (
        JSONWebKey.generate(alg='A128GCMKW'),
    ),
    (
        JSONWebKey.generate(alg='A128GCMKW'),
        JSONWebKey.generate(alg='ECDH-ES+A128KW', crv='P-256'),
    )
]

PAYLOADS: list[bytes | JSONWebToken] = [
    b'Hello world!',
    JSONWebToken(iss='https://example.local'),
    CustomTokenSchema(foo='bar')
]


@pytest.mark.asyncio
@pytest.mark.parametrize("recipients", RECIPIENTS)
@pytest.mark.parametrize("signers", SIGNERS)
@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("include_keys", [True, False])
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
async def test_builder_creates_validatable_tokens(
    signers: list[JSONWebKey],
    recipients: list[JSONWebKey],
    payload: bytes | JSONWebToken,
    include_keys: bool,
    syntax: SerializationFormat
):
    cls = type(payload)
    if not signers and not recipients:
        pytest.skip("No signers and no recipients.")
    if (len(signers) > 1 and not recipients) and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple signers.")
    if len(recipients) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple recipients.")
    validator = TokenValidator(
        cls,
        keys=signers
    )
    builder = TokenBuilder(
        cls,
        include_keys=include_keys
    )
    builder.payload(payload)
    for signer in signers:
        builder.sign(signer)
    for recipient in recipients:
        builder.encrypt(recipient, enc='A128GCM')
    token = await builder.build(syntax=syntax)

    # Compact encoding must always serialize to the base64 encoded
    # string.
    adapter: pydantic.TypeAdapter[JWSCompactEncoded | JWECompactEncoded] = pydantic.TypeAdapter(
        JWSCompactEncoded | JWECompactEncoded
    )
    if syntax == 'compact':
        token = adapter.validate_python(token)
        if recipients:
            assert isinstance(token, JWECompactEncoded)
        if signers and not recipients:
            assert isinstance(token, JWSCompactEncoded)

    # Check if the token can be decoded using the given syntax.
    jws = token
    if not recipients:
        assert validator.deserialize('jws', syntax, jws)

        # Inspect the JWS headers,
        *_, headers = validator.inspect(jws)
        assert len(headers) == len(signers)
        for header, signer in zip(headers, signers):
            if signer.kid:
                assert header.kid == signer.kid
            if signer.x5t:
                assert header.x5t == signer.x5t
            if include_keys:
                assert header.jwk is not None
                assert header.jwk == signer.public

        # Validator the complete token and inspect its contents.
        value = await validator.validate(jws)
        assert isinstance(value, cls)
        assert payload == value
        if isinstance(payload, JSONWebToken):
            assert isinstance(value, JSONWebToken)
            assert payload.iss == value.iss