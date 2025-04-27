from typing import Any

import pytest

from aegisx.core.crypto import Algorithm


SUPPORTED_HASHES = ['sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b512', 'blake2s256']


@pytest.mark.parametrize("params", [
    {'name': 'ES256'},
    {'name': 'ES384'},
    {'name': 'ES512'},
    {'name': 'BS256'},
    {'name': 'BS384'},
    {'name': 'BS512'},
])
def test_elliptic_curve_sign_with_named_algorithm(
    params: dict[str, Any]
):
    msg = b'Hello world!'
    alg = Algorithm.model_validate(params)
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=False)
    assert alg.verify(key.public_key(), sig, msg, prehashed=False)


@pytest.mark.parametrize("crv", [
    "P-256",
    "P-384",
    "P-521",
    "B-256",
    "B-384",
    "B-512",
    "P-256K",
])
@pytest.mark.parametrize("prehashed", [True, False])
@pytest.mark.parametrize("dig", SUPPORTED_HASHES)
def test_elliptic_curve_sign_dynamic(
    crv: str,
    dig: str,
    prehashed: bool
):
    alg = Algorithm.model_validate({
        'crv': crv,
        'dig': dig
    })
    msg = b'Hello world!'
    if prehashed:
        assert alg.dig
        msg = alg.dig.digest(msg)
    key = alg.generate()
    sig = alg.sign(key, msg, prehashed=prehashed)
    assert alg.verify(key.public_key(), sig, msg, prehashed=prehashed)
