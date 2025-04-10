import pydantic
import pytest

from aegisx.ext.jose.models import JWSHeader


# For a JWS, the members of the JSON object(s) representing the JOSE
# Header describe the digital signature or MAC applied to the JWS
# Protected Header and the JWS Payload and optionally additional
# properties of the JWS.  The Header Parameter names within the JOSE
# Header MUST be unique; JWS parsers MUST either reject JWSs with
# duplicate Header Parameter names or use a JSON parser that returns
# only the lexically last duplicate member name, as specified in
# Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].
def test_header_parses_last_header_name():
    header = JWSHeader.model_validate_json('{"alg": "RS256", "alg": "RS384"}')
    assert header.alg == 'RS384'

# Implementations are required to understand the specific Header
# Parameters defined by this specification that are designated as "MUST
# be understood" and process them in the manner defined in this
# specification.  All other Header Parameters defined by this
# specification that are not so designated MUST be ignored when not
# understood.  Unless listed as a critical Header Parameter, per
# Section 4.1.11, all Header Parameters not defined by this
# specification MUST be ignored when not understood.
def test_unknown_critical_headers_raises_validationerror():
    with pytest.raises(pydantic.ValidationError):
        JWSHeader.model_validate({
            'crit': ['foo'],
            'foo': 'foo'
        })