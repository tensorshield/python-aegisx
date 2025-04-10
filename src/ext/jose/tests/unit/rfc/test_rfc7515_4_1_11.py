import pydantic
import pytest

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder
from .conftest import JOSEType
from .conftest import INPUT_FORMATS


# Implementations are required to understand the specific Header
# Parameters defined by this specification that are designated as "MUST
# be understood" and process them in the manner defined in this
# specification.  All other Header Parameters defined by this
# specification that are not so designated MUST be ignored when not
# understood.  Unless listed as a critical Header Parameter, per
# Section 4.1.11, all Header Parameters not defined by this
# specification MUST be ignored when not understood.
@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_unknown_critical_headers_raises_validationerror(
    adapter: pydantic.TypeAdapter[JOSEType],
    sig: JSONWebKey,
    syntax: TokenBuilder.SerializationFormat,
):
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(sig, alg='ES256', crit=['foo'])\
        .build(syntax=syntax, mode='python')
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python(token)