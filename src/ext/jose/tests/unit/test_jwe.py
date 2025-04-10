import pydantic
import pytest

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import Undecryptable
from aegisx.ext.jose.models import JSONWebEncryption
from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.jose.models import JWEHeader
from aegisx.ext.jose.models import JWEGeneralSerialization


DEFAULT_ALG = JSONWebAlgorithm.validate('A128GCM')


@pytest.mark.asyncio
async def test_can_not_decrypt_empty_jwe(enc: JSONWebKey):
    jwe = JSONWebEncryption(b'Hello world')
    with pytest.raises(Undecryptable):
        await jwe.decrypt(enc)


def test_encrypt_requires_alg(enc: JSONWebKey):
    jwe = JSONWebEncryption(b'Hello world')
    with pytest.raises(TypeError):
        enc.root.alg = None
        jwe.encrypt(enc)


def test_dump_does_not_contain_plaintext(enc: JSONWebKey):
    jwe = JSONWebEncryption(b'Hello world')
    assert isinstance(jwe.root, JWEGeneralSerialization)
    data = jwe.model_dump()
    assert isinstance(data, dict)
    assert 'plaintext' not in data


def test_serialization_sets_cty_header_bytes(enc: JSONWebKey):
    jwe = JSONWebEncryption(b'Hello world!')
    assert jwe.header.cty == 'application/octet-stream'


def test_jwe_header_must_understand_critical():
    with pytest.raises(pydantic.ValidationError):
        JWEHeader(alg=DEFAULT_ALG, crit=["foo"])


@pytest.mark.parametrize("name", JWEHeader.forbidden_critical_claims)
def test_jwe_header_must_not_be_from_specification(name: str):
    with pytest.raises(pydantic.ValidationError):
        JWEHeader(alg=DEFAULT_ALG, crit=[name])


def test_jwe_crit_must_not_contain_duplicates():
    with pytest.raises(pydantic.ValidationError):
        JWEHeader(alg=DEFAULT_ALG, crit=["foo", "foo"])


def test_jwe_crit_must_not_be_empty():
    with pytest.raises(pydantic.ValidationError):
        JWEHeader(alg=DEFAULT_ALG, crit=[])


def test_jwe_crit_must_be_protected(enc: JSONWebKey):
    jwe = JSONWebEncryption(b'Hello world!')
    with pytest.raises(ValueError):
        jwe.encrypt(enc, header={'crit': ['iss']})