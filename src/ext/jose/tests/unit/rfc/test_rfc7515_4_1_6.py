import pydantic
import pytest
from cryptography.x509 import Certificate

from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import TokenBuilder

from .conftest import JOSEType
from .conftest import INPUT_FORMATS


# The certificate containing the public key corresponding to
# the key used to digitally sign the JWS MUST be the first certificate.
@pytest.mark.asyncio
@pytest.mark.parametrize("syntax", INPUT_FORMATS)
async def test_valid_chain_is_accepted(
    adapter: pydantic.TypeAdapter[JOSEType],
    syntax: TokenBuilder.SerializationFormat,
    x5c_valid_chain: tuple[Certificate, JSONWebKey, list[str]]
):
    _, key, chain = x5c_valid_chain
    token = await TokenBuilder(bytes)\
        .payload(b'Hello world!')\
        .sign(key, alg='ES256', x5c=chain)\
        .build(syntax=syntax, mode='python')
    adapter.validate_python(token)