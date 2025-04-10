import pydantic
import pytest

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JWSCompactEncoded
from aegisx.ext.jose.models import JSONWebSignature
from aegisx.ext.jose.models import JSONWebToken
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JWSHeader


DEFAULT_ALG = JSONWebAlgorithm.validate('HS256')


@pytest.mark.asyncio
async def test_unsigned_jws_is_not_verified(sig: JSONWebKey):
    jws = JSONWebSignature({})
    assert not await jws.verify(sig)


@pytest.mark.asyncio
async def test_serialization_sets_typ_header_jwt(sig: JSONWebKey):
    jwt = JSONWebToken()
    jws = JSONWebSignature(JWSCompactEncoded(await JSONWebSignature(jwt.claims).sign(sig)))
    assert jws.signatures[0].claims.get('typ') == 'application/jwt'


@pytest.mark.asyncio
async def test_serialization_sets_cty_header_jwt(sig: JSONWebKey):
    jwt = JSONWebToken()
    jws = JSONWebSignature(JWSCompactEncoded(await JSONWebSignature(jwt.claims).sign(sig)))
    assert jws.signatures[0].claims.get('cty') == 'application/jwt'


@pytest.mark.asyncio
async def test_serialization_sets_cty_header_octet_stream(sig: JSONWebKey):
    jws = JSONWebSignature(JWSCompactEncoded(await JSONWebSignature(b'Hello world!').sign(sig)))
    assert jws.signatures[0].claims.get('cty') == 'application/octet-stream'
    #raise Exception(JWSCompactEncoded(await JSONWebSignature(b'Hello world!').sign(sig)))


def test_cty_is_converted_to_application():
    header = JWSHeader(alg=DEFAULT_ALG, cty='foo')
    assert header.cty == 'application/foo'


# RFC 7515: 4.1.11.  "crit" (Critical) Header Parameter
#
# The "crit" (critical) Header Parameter indicates that extensions to
# this specification and/or [JWA] are being used that MUST be
# understood and processed.  Its value is an array listing the Header
# Parameter names present in the JOSE Header that use those extensions.
# If any of the listed extension Header Parameters are not understood
# and supported by the recipient, then the JWS is invalid.  Producers
# MUST NOT include Header Parameter names defined by this specification
# or [JWA] for use with JWS, duplicate names, or names that do not
# occur as Header Parameter names within the JOSE Header in the "crit"
# list.  Producers MUST NOT use the empty list "[]" as the "crit"
# value.  Recipients MAY consider the JWS to be invalid if the critical
# list contains any Header Parameter names defined by this
# specification or [JWA] for use with JWS or if any other constraints
# on its use are violated.  When used, this Header Parameter MUST be
# integrity protected; therefore, it MUST occur only within the JWS
# Protected Header.  Use of this Header Parameter is OPTIONAL.  This
# Header Parameter MUST be understood and processed by implementations.
def test_jws_header_must_understand_critical():
    with pytest.raises(pydantic.ValidationError):
        JWSHeader(alg=DEFAULT_ALG, crit=["foo"])


@pytest.mark.parametrize("name", [field.alias or name for name, field in JWSHeader.model_fields.items()])
def test_jws_header_must_not_be_from_specification(name: str):
    with pytest.raises(pydantic.ValidationError):
        JWSHeader(alg=DEFAULT_ALG, crit=[name])


def test_jws_crit_must_not_contain_duplicates():
    with pytest.raises(pydantic.ValidationError):
        JWSHeader(alg=DEFAULT_ALG, crit=["foo", "foo"])


def test_jws_crit_must_not_be_empty():
    with pytest.raises(pydantic.ValidationError):
        JWSHeader(alg=DEFAULT_ALG, crit=[])


def test_jws_crit_must_be_protected(sig: JSONWebKey):
    jws = JSONWebSignature({})
    with pytest.raises(pydantic.ValidationError):
        jws.sign(sig, header={'crit': ['foo']})


def test_jws_rejects_http_jku():
    with pytest.raises(ValueError):
        JWSHeader.model_validate({
            'alg': DEFAULT_ALG,
            'jku': 'http://www.foo.com'
        })


def test_jws_rejects_http_x5u():
    with pytest.raises(ValueError):
        JWSHeader.model_validate({
            'alg': DEFAULT_ALG,
            'x5u': 'http://www.foo.com'
        })


# Test jws does not contain claims or jws header