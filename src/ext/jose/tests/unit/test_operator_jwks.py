import tempfile
import os

from aegisx.ext.jose.models import JSONWebKeySet


def test_union(
    jwks_ec: JSONWebKeySet,
    jwks_rsa: JSONWebKeySet
):
    assert len(jwks_ec | jwks_rsa) == 3


def test_contains(
    jwks_ec: JSONWebKeySet,
    jwks_rsa: JSONWebKeySet
):
    assert jwks_ec.keys[0] in jwks_ec
    assert jwks_ec.keys[0] not in jwks_rsa


def test_update(jwks_ec: JSONWebKeySet,):
    jwks = JSONWebKeySet()
    jwks.update(jwks_ec)
    assert len(jwks) == len(jwks_ec)
    assert jwks.thumbprints() == jwks_ec.thumbprints()


def test_write(jwks_ec: JSONWebKeySet):
    fn = os.path.join(tempfile.gettempdir(), bytes.hex(os.urandom(16)))
    jwks_ec.write(fn)
    assert os.path.exists(fn)


def test_fromfile(jwks_ec: JSONWebKeySet):
    fn = os.path.join(tempfile.gettempdir(), bytes.hex(os.urandom(16)))
    jwks_ec.write(fn)
    jwks = JSONWebKeySet.fromfile(fn)
    assert jwks.thumbprints() == jwks_ec.thumbprints()