import pydantic
import pytest

from aegisx.ext.jose.models import JSONWebKey
from aegisx.ext.iam.models import AuthorizedKey


def test_key_must_be_public(sig: JSONWebKey):
    with pytest.raises(pydantic.ValidationError):
        AuthorizedKey.model_validate({
            'email': 'test@tensorshield.ai',
            'key': sig,
            'host': '127.0.0.1'
        })


def test_key_must_be_symmetric():
    with pytest.raises(pydantic.ValidationError):
        AuthorizedKey.model_validate({
            'email': 'test@tensorshield.ai',
            'key': JSONWebKey.generate(alg='A128GCM', kty='oct', length=32),
            'host': '127.0.0.1'
        })


def test_key_thumbprint_matches_input(sig: JSONWebKey):
    key = AuthorizedKey.model_validate({
        'email': 'test@tensorshield.ai',
        'key': sig.public,
        'host': '127.0.0.1'
    })
    assert sig.public
    assert key.thumbprint == sig.public.thumbprint('sha256')