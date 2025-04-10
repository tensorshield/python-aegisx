import pytest

from cryptography.x509 import Certificate

from aegisx.ext.jose.types import X509CertificateChain
from aegisx.ext.jose import JSONWebKey



def test_with_valid_chain(
    x5c_root_crt: Certificate,
    x5c_valid_chain: tuple[Certificate, JSONWebKey, list[str]]
):
    *_, chain = x5c_valid_chain
    assert len(chain) == 2
    pytest.skip("Further testing needs cryptography==45.0.0")


def test_serialize(x5c_valid_chain: tuple[Certificate, JSONWebKey, list[str]]):
    *_, chain = x5c_valid_chain
    x5c = X509CertificateChain.fromlist(chain)
    assert chain == x5c.serialize()