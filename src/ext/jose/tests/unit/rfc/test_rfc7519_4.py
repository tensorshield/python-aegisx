import pytest

from aegisx.ext.jose import JSONWebToken


# The JWT Claims Set represents a JSON object whose members are the
# claims conveyed by the JWT.  The Claim Names within a JWT Claims Set
# MUST be unique; JWT parsers MUST either reject JWTs with duplicate
# Claim Names or use a JSON parser that returns only the lexically last
# duplicate member name, as specified in Section 15.12 ("The JSON
# Object") of ECMAScript 5.1 [ECMAScript].
@pytest.mark.asyncio
async def test_duplicate_claims_model_parses_last():
    token = JSONWebToken.model_validate_json('{"iss": "1", "iss": "2"}')
    assert token.iss == "2"