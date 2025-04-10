import pytest

from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import TokenValidator


# The "jti" (JWT ID) claim provides a unique identifier for the JWT.
# The identifier value MUST be assigned in a manner that ensures that
# there is a negligible probability that the same value will be
# accidentally assigned to a different data object; if the application
# uses multiple issuers, collisions MUST be prevented among values
# produced by different issuers as well.
@pytest.mark.asyncio
async def test_jti_can_not_be_reused():
    validator = TokenValidator(JSONWebToken)
    jwt = JSONWebToken.model_validate({'jti': '123'})
    assert jwt.jti
    await validator.validate_token(jwt)
    with pytest.raises(ValueError):
        await validator.validate_token(jwt)