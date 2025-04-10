import pytest

from cryptography.x509 import Certificate

from aegisx.ext.jose.types import X509CertificateChain



def test_with_valid_chain(
    x5c_root_crt: Certificate,
    x5c_valid_chain: list[str]
):
    assert len(x5c_valid_chain) == 2
    pytest.skip("Further testing needs cryptography==45.0.0")


def test_serialize(x5c_valid_chain: list[str]):
    x5c = X509CertificateChain.fromlist(x5c_valid_chain)
    assert x5c_valid_chain == x5c.serialize()