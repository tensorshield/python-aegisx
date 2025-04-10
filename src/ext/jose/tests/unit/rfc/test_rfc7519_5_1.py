import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import SerializationFormat
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator

from .conftest import INPUT_FORMATS


# The "typ" (type) Header Parameter defined by [JWS] and [JWE] is
# used by JWT applications to declare the media type [IANA.MediaTypes]
# of this complete JWT.  This is intended for use by the JWT application
# when values that are not JWTs could also be present in an application
# data structure that can contain a JWT object; the application can use
# this value to disambiguate among the different kinds of objects that
# might be present.  It will typically not be used by applications when
# it is already known that the object is a JWT.  This parameter is
# ignored by JWT implementations; any processing of this parameter is
# performed by the JWT application.  If present, it is RECOMMENDED that
# its value be "JWT" to indicate that this object is a JWT.  While media
# type names are not case sensitive, it is RECOMMENDED that "JWT" always
# be spelled using uppercase characters for compatibility with legacy implementations.
# Use of this Header Parameter is OPTIONAL.
@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_jws_has_typ_header(
    syntax: SerializationFormat,
    sig: JSONWebKey
):
    validator = TokenValidator(JSONWebToken)
    encoded = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .sign(sig)\
        .build(syntax=syntax)
    protected, unprotected, headers = validator.inspect(encoded)
    assert protected is None
    assert unprotected is None
    assert all([x.typ == 'application/jwt' for x in headers]), headers


@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_jwe_has_typ_header(
    syntax: SerializationFormat,
    enc: JSONWebKey
):
    validator = TokenValidator(JSONWebToken)
    encoded = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .encrypt(enc, enc='A128GCM')\
        .build(syntax=syntax)
    protected, unprotected, _ = validator.inspect(encoded)
    assert protected is not None
    assert unprotected is not None
    assert protected.typ == "application/jwt", protected
    assert not protected.cty