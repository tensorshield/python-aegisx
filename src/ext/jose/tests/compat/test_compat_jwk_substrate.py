import os
from scalecodec.utils.ss58 import ss58_encode
from substrateinterface import Keypair
from substrateinterface import KeypairType

from aegisx.ext.jose import JSONWebKey


SS58_FORMAT = 42


def test_public_key_matches():
    k1 = JSONWebKey.generate(kty='OKP', crv='Ed25519')
    k2 = Keypair(
        ss58_address=ss58_encode(k1.public_bytes),
        ss58_format=SS58_FORMAT,
        crypto_type=KeypairType.ED25519
    )
    assert k2.public_key == k1.public_bytes


def test_our_signature_their_verification_ed25519():
    message = b'Hello world'
    k1 = JSONWebKey.generate(kty='OKP', crv='Ed25519')
    k2 = Keypair(
        ss58_address=ss58_encode(k1.public_bytes),
        ss58_format=SS58_FORMAT,
        crypto_type=KeypairType.ED25519
    )
    sig = bytes(k1.sign(message))
    assert k2.verify(message, sig)


def test_their_signature_our_verification_ed25519():
    message = b'Hello world'
    k1 = Keypair.create_from_seed(
        seed_hex=bytes.hex(os.urandom(32)),
        ss58_format=SS58_FORMAT,
        crypto_type=KeypairType.ED25519
    )
    k2 = JSONWebKey(kty='OKP', alg='EdDSA', crv='Ed25519', public_bytes=k1.public_key)

    sig = k1.sign(message)
    assert k1.public_key == k2.public_bytes
    assert bool(k2.verify(sig, message, k2.alg))