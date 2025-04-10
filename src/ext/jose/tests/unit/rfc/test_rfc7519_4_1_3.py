from typing import Any

import pydantic
import pytest

from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenValidator


# If the principal processing the claim does not identify itself
# with a value in the "aud" claim when this claim is present,
# then the JWT MUST be rejected.
@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [None, "https://tensorshield.ai", {"https://tensorshield.ai", "https://test.tensorshield.ai"}])
@pytest.mark.parametrize("audience", ["https//google.com", "https://tensorshield.ai/foo"])
async def test_invalid_audience_is_rejected(
    accepted: str | None,
    audience: str
):
    payload: dict[str, Any] = {
        'aud': audience
    }
    with pytest.raises(pydantic.ValidationError):
        TokenValidator(JSONWebToken, audience=accepted)\
            .validate_payload(payload)


@pytest.mark.asyncio
async def test_single_audience_is_serialized_to_string():
    token = JSONWebToken(aud={'https:/foo.com'})
    claims = token.model_dump()
    assert isinstance(claims['aud'], str)