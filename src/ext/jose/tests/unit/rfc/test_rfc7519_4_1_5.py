from typing import Any

import pydantic
import pytest

from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenValidator


# The "exp" (expiration time) claim identifies the expiration time on or
# after which the JWT MUST NOT be accepted for processing.  The
# processing of the "exp" claim requires that the current date/time
# MUST be before the expiration date/time listed in the "exp" claim.
@pytest.mark.asyncio
@pytest.mark.parametrize("now,nbf,max_clock_skew", [(0, 1, 0), (0, 30, 30)])
async def test_inactive_token_is_rejected(
    now: int,
    nbf: int,
    max_clock_skew: int
):
    payload: dict[str, Any] = {
        'nbf': nbf
    }
    with pytest.raises(pydantic.ValidationError):
        TokenValidator(JSONWebToken, max_clock_skew=max_clock_skew, context={'now': now})\
            .validate_payload(payload)