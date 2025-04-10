import pydantic
import pytest
from libcanonical.utils.encoding import b64encode_json

from aegisx.ext.jose.models import JWSFlattenedSerialization


# In the JWS JSON Serialization, one or both of the JWS Protected
# Header and JWS Unprotected Header MUST be present.  In this case, the
# members of the JOSE Header are the union of the members of the JWS
# Protected Header and the JWS Unprotected Header values that are
# present.
def test_flattened_protected_or_unprotected_must_be_present():
    # Protected
    JWSFlattenedSerialization[bytes].model_validate({
        'protected': b64encode_json({'alg': 'RS256'}, encoder=str),
        'signature': '',
        'payload': '',
    })

    # Unprotected
    JWSFlattenedSerialization[bytes].model_validate({
        'header': {'alg': 'RS256'},
        'signature': '',
        'payload': '',
    })
    with pytest.raises(pydantic.ValidationError):
        JWSFlattenedSerialization[bytes].model_validate({
            'signature': '',
            'payload': ''
        })