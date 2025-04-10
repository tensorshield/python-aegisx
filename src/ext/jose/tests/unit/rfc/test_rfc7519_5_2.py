import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import SerializationFormat
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator

from .conftest import INPUT_FORMATS


# The "cty" (content type) Header Parameter defined by [JWS] and
# [JWE] is used by this specification to convey structural
# information about the JWT. In the normal case in which nested
# signing or encryption operations are not employed, the use of
# this Header Parameter is NOT RECOMMENDED.  In the case that
# nested signing or encryption is employed, this Header Parameter
# MUST be present; in this case, the value MUST be "JWT", to
# indicate that a Nested JWT is carried in this JWT.  While media
# type names are not case sensitive, it is RECOMMENDED that "JWT"
# always be spelled using uppercase characters for compatibility
# with legacy implementations.
@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_jwe_has_cty_header(
    syntax: SerializationFormat,
    enc: JSONWebKey,
    sig: JSONWebKey
):
    validator = TokenValidator(JSONWebToken)
    encoded = await TokenBuilder(JSONWebToken)\
        .update(iss='foo')\
        .sign(sig)\
        .encrypt(enc, enc='A128GCM')\
        .build(syntax=syntax)
    protected, unprotected, _ = validator.inspect(encoded)
    assert protected is not None
    assert unprotected is not None
    assert protected.typ == "application/jwt", protected
    assert protected.cty == "application/jwt", protected