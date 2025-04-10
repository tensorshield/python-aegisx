from typing import Any

import pydantic
import pytest

from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenValidator


# The "iat" (issued at) claim identifies the time at which the JWT
# was issued.  This claim can be used to determine the age of the
# JWT.  Its value MUST be a number containing a NumericDate value. 
# Use of this claim is OPTIONAL.
@pytest.mark.asyncio
@pytest.mark.parametrize("value", ['2024-01-01'])
async def test_iat_must_be_numericdate(
    value: str
):
    payload: dict[str, Any] = {
        'iat': value
    }
    with pytest.raises(pydantic.ValidationError):
        TokenValidator(JSONWebToken)\
            .validate_payload(payload)