import json
import time

import pydantic
import pytest

from aegisx.ext.jose.models import JSONWebToken
from aegisx.ext.jose.types import ForbiddenAudience
from aegisx.ext.jose.types import MissingAudience


@pytest.mark.parametrize("now", [int(time.time()), 0, None])
def test_exp_must_be_lt_now(now: int | None):
    with pytest.raises(pydantic.ValidationError):
        JSONWebToken.deserialize({'exp': 1}, now=now)


@pytest.mark.parametrize("now", [int(time.time()), None])
def test_nbf_must_be_gt_now(now: int | None):
    with pytest.raises(pydantic.ValidationError):
        JSONWebToken.deserialize({'nbf': int(time.time()) + 1}, now=now)


def test_deserialize_jwt():
    JSONWebToken.deserialize({
        'exp': int(time.time()) + 1,
        'nbf': int(time.time()) - 1
    })


def test_deserialize_json():
    JSONWebToken.deserialize(json.dumps({
        'exp': int(time.time()) + 1,
        'nbf': int(time.time()) - 1
    }))


def test_aud_is_parsed_to_set():
    jwt = JSONWebToken.deserialize({'aud': 'foo'})
    assert isinstance(jwt.aud, set)


def test_aud_is_parsed_to_scalar():
    jwt = JSONWebToken.deserialize({'aud': {'foo'}})
    data = jwt.model_dump()
    assert isinstance(data['aud'], str), data['aud']
    assert data['aud'] == 'foo'


def test_aud_is_parsed_to_scalar_json():
    jwt = JSONWebToken.deserialize({'aud': {'foo'}})
    data = json.loads(jwt.model_dump_json())
    assert isinstance(data['aud'], str), data['aud']
    assert data['aud'] == 'foo'


def test_validate_aud_illegal_single():
    with pytest.raises(ForbiddenAudience):
        JSONWebToken.deserialize(
            {'aud': 'foo'},
            audiences={'bar', 'baz'}
        )


def test_validate_aud_illegal_multi():
    with pytest.raises(ForbiddenAudience):
        JSONWebToken.deserialize(
            {'aud': {'foo', 'qux'}},
            audiences={'bar', 'baz'}
        )


def test_validate_aud_missing():
    # Skip because we assume that if the aud claim is None, the token
    # may be used with any audience.
    pytest.skip("Not implemented")
    with pytest.raises(MissingAudience):
        JSONWebToken.deserialize(
            {},
            audiences={'bar', 'baz'}
        )