import pytest
import pydantic
import hashlib

from libcanonical.types import Base64URLEncoded

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import SerializationFormat
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JWEHeader
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
@pytest.mark.parametrize("audience", [None, "https://example.com", {"https://example.com"}])
async def test_builder_creates_validatable_tokens(
    signers: list[JSONWebKey],
    recipients: list[JSONWebKey],
    payload: bytes | JSONWebToken,
    include_keys: bool,
    syntax: SerializationFormat,
    audience: None | str | set[str]
):
    cls = type(payload)
    if not isinstance(payload, JSONWebToken) and audience is not None:
        pytest.skip("Audience claim not supported.")
    if not signers and not recipients:
        pytest.skip("No signers and no recipients.")
    if (len(signers) > 1 and not recipients) and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple signers.")
    if len(recipients) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple recipients.")
    validator = TokenValidator(
        cls,
        keys=signers,
        audience=audience,
        issuer=None if not isinstance(payload, JSONWebToken) else payload.iss
    )
    builder = TokenBuilder(
        cls,
        include_keys=include_keys
    )
    builder.payload(payload)
    if audience is not None and isinstance(payload, JSONWebToken):
        builder.audience(audience)
    for signer in signers:
        builder.sign(signer)
    for recipient in recipients:
        builder.encrypt(recipient, enc='A128GCM')
    token = await builder.build(syntax=syntax)

    # Builder must retain the plaintext if encrypting.
    if recipients and not signers and isinstance(payload, bytes):
        # TODO: JWT test not supported.
        assert builder.plaintext == payload

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
            if signer.x5t_s256:
                assert header.x5t_s256 == signer.x5t_s256
            if include_keys:
                assert header.jwk is not None
                assert header.jwk == signer.public
            if isinstance(payload, bytes):
                assert header.cty == 'application/octet-stream'

        # Validator the complete token and inspect its contents.
        value = await validator.validate(jws)
        assert isinstance(value, cls)
        if isinstance(payload, bytes):
            # JSONWebToken is not evaluated as we add stuff to it (TODO)
            assert payload == value
        if isinstance(payload, JSONWebToken):
            assert isinstance(value, JSONWebToken)
            assert payload.iss == value.iss


@pytest.mark.asyncio
@pytest.mark.parametrize("signers", [
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t_sha256=Base64URLEncoded(hashlib.sha256().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', kid='foo'),
    ),
])
@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
@pytest.mark.parametrize("include_keys", [True, False])
async def test_builder_sets_key_claims_on_jws_header(
    signers: list[JSONWebKey],
    payload: bytes | JSONWebToken,
    syntax: SerializationFormat,
    include_keys: bool
):
    cls = type(payload)
    validator = TokenValidator(cls, keys=signers)
    builder = TokenBuilder(cls)
    builder.payload(payload)
    for signer in signers:
        builder.sign(signer, include=include_keys)
    token = await builder.build(syntax=syntax)
    assert validator.deserialize('jws', syntax, token)

    # Compact encoding must always serialize to the base64 encoded
    # string.
    adapter: pydantic.TypeAdapter[JWSCompactEncoded] = pydantic.TypeAdapter(
        JWSCompactEncoded
    )
    if syntax == 'compact':
        assert adapter.validate_python(token)

    # Inspect the JWS headers,
    *_, headers = validator.inspect(token)
    assert len(headers) == len(signers)
    for header, signer in zip(headers, signers):
        if signer.kid:
            assert header.kid == signer.kid
        if signer.x5t:
            assert header.x5t == signer.x5t
        if signer.x5t_s256:
            assert header.x5t_s256 == signer.x5t_s256
        if include_keys:
            assert header.jwk is not None
            assert header.jwk == signer.public


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
@pytest.mark.parametrize("signers", [
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
])
async def test_jws_force_typ(
    syntax: SerializationFormat,
    signers: list[JSONWebKey],
    payload: bytes | JSONWebToken
):
    if len(signers) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple signers.")
    cls = type(payload)
    typ = 'foo'
    validator = TokenValidator(cls, keys=signers)
    builder = TokenBuilder(cls)
    builder.payload(payload, typ=typ)
    for signer in signers:
        builder.sign(signer)
    token = await builder.build(syntax=syntax)
    assert validator.deserialize('jws', syntax, token)
    *_, headers = validator.inspect(token)
    assert len(headers) == len(signers)
    for header, signer in zip(headers, signers):
        assert header.typ == f'application/{typ}'


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
@pytest.mark.parametrize("signers", [
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
])
async def test_jws_force_cty(
    syntax: SerializationFormat,
    signers: list[JSONWebKey],
    payload: bytes | JSONWebToken
):
    if len(signers) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple signers.")
    cls = type(payload)
    cty = 'foo'
    validator = TokenValidator(cls, keys=signers)
    builder = TokenBuilder(cls)
    builder.payload(payload, cty=cty)
    for signer in signers:
        builder.sign(signer)
    token = await builder.build(syntax=syntax)
    assert validator.deserialize('jws', syntax, token)
    *_, headers = validator.inspect(token)
    assert len(headers) == len(signers)
    for header, signer in zip(headers, signers):
        assert header.cty == f'application/{cty}'


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [JSONWebToken()])
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
@pytest.mark.parametrize("signers", [
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
    (
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
        JSONWebKey.generate(alg='EdDSA', crv='Ed25519', x5t=Base64URLEncoded(hashlib.sha1().digest())),
    ),
])
@pytest.mark.parametrize("autoinclude", [{"iat"}, {"nbf"}, {"iat", "nbf"}])
async def test_jws_autoincludes_claims(
    syntax: SerializationFormat,
    signers: list[JSONWebKey],
    payload: bytes | JSONWebToken,
    autoinclude: set[str]
):
    if len(signers) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple signers.")
    cls = type(payload)
    cty = 'foo'
    validator = TokenValidator(cls, keys=signers)
    builder = TokenBuilder(cls, autoinclude=autoinclude)
    builder.payload(payload, cty=cty)
    for signer in signers:
        builder.sign(signer)
    token = await validator.validate(await builder.build(syntax=syntax))
    for attname in autoinclude:
        assert getattr(token, attname, None) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [
    JSONWebToken(iss='foo'),
    JSONWebToken(aud={'bar'}),
    JSONWebToken(sub='baz')
])
@pytest.mark.parametrize("syntax", ['compact', 'general', 'general'])
@pytest.mark.parametrize("recipients", RECIPIENTS[1:])
async def test_jwe_replicates_claims(
    syntax: SerializationFormat,
    recipients: list[JSONWebKey],
    payload: JSONWebToken
):
    if len(recipients) > 1 and syntax == 'compact':
        pytest.skip("Compact encoding can not be used with multiple recipients.")
    cls = type(payload)
    validator = TokenValidator(cls, keys=recipients)
    builder = TokenBuilder(cls, replicate_claims=True)
    builder.payload(payload)
    for recipient in recipients:
        builder.encrypt(recipient, enc='A128GCM')
    token = await builder.build(syntax=syntax)
    protected, *_ = validator.inspect(token)
    assert isinstance(protected, JWEHeader)
    assert protected.iss == payload.iss
    assert protected.aud == payload.aud
    assert protected.sub == payload.sub