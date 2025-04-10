import pydantic
import pytest

from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose.models import JWSCompactSerialization
from aegisx.ext.jose.models import JWSFlattenedSerialization


# The "alg" (algorithm) Header Parameter identifies the cryptographic
# algorithm used to secure the JWS.  The JWS Signature value is not
# valid if the "alg" value does not represent a supported algorithm or
# if there is not a key for use with that algorithm associated with the
# party that digitally signed or MACed the content.  "alg" values
# should either be registered in the IANA "JSON Web Signature and
# Encryption Algorithms" registry established by [JWA] or be a value
# that contains a Collision-Resistant Name.  The "alg" value is a case-
# sensitive ASCII string containing a StringOrURI value.  This Header
# Parameter MUST be present and MUST be understood and processed by
# implementations.
def test_compact_requires_alg_header():
    with pytest.raises(pydantic.ValidationError):
        JWSCompactSerialization.model_validate({
            'protected': b64encode_json({}, encoder=str),
            'signature': '',
            'payload': b''
        })

def test_flattened_requires_alg_header():
    with pytest.raises(pydantic.ValidationError):
        JWSFlattenedSerialization[bytes].model_validate({
            'protected': b64encode_json({}, encoder=str),
            'header': {},
            'signature': '',
            'payload': b'',
        })