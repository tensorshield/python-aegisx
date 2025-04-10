import pytest
from substrateinterface.keypair import Keypair

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.models.jwk import JSONWebKeySR25519Private
from aegisx.ext.jose.models.jwk import JSONWebKeySR25519Public
from aegisx.ext.jose.models import JSONWebKey


def test_key_generation(
    sr25519_signing_key: JSONWebKeySR25519Private
):
    kp = Keypair.create_from_private_key(sr25519_signing_key.d, ss58_format=42)
    assert kp.ss58_address == sr25519_signing_key.public.kid


def test_create_from_seed():
    k1 = JSONWebKeySR25519Private.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    k2 = Keypair.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    assert k1.kid == k2.ss58_address
    assert k1.x == k2.public_key
    assert k1.d == k2.private_key


def test_create_from_private_key():
    k1 = JSONWebKeySR25519Private.create_from_private_key('0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f')
    k2 = Keypair.create_from_private_key('0x2b400f61c21cbaad4d5cb2dcbb4ef4fcdc238b98d04d48c6d2a451ebfd306c0eed845edcc69b0a19a6905afed0dd84c16ebd0f458928f2e91a6b67b95fc0b42f', ss58_format=42)
    assert k1.kid == k2.ss58_address
    assert k1.x == k2.public_key
    assert k1.d == k2.private_key


@pytest.mark.asyncio
async def test_our_signature_their_verification():
    k1 = JSONWebKeySR25519Private.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    k2 = Keypair.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    assert k2.verify(b'asd', await k1.sign(b'asd'))


@pytest.mark.asyncio
async def test_their_signature_our_verification():
    k1 = JSONWebKeySR25519Private.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    k2 = Keypair.create_from_seed('0x023d5fbd7981676587a9f7232aeae1087ac7c265f9658fb643b6f5e61961dfbf')
    assert await k1.verify(k2.sign(b'asd'), b'asd', JSONWebAlgorithm.validate('EdDSA'))


def test_create_from_ss58_address():
    k = JSONWebKey.model_validate({
        'ss58_address': '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'
    })
    assert k.kid == '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'


def test_from_constructor():
    k = JSONWebKey(ss58_address='5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY')
    assert isinstance(k.root, JSONWebKeySR25519Public)
    assert k.kid == '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'