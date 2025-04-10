import pydantic
import pytest

from aegisx.ext.oauth.models import ClaimRequest


def test_value_is_added_to_values():
    c = ClaimRequest[str].model_validate({
        'value': 'foo'
    })
    assert c.values == ['foo']


def test_value_xor_values():
    with pytest.raises(pydantic.ValidationError):
        ClaimRequest.model_validate({'value': 'foo', 'values': ['foo']})


def test_value_is_type_coerced():
    adapter = pydantic.TypeAdapter(ClaimRequest[int])
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python({'value': 'foo'})


def test_values_is_type_coerced():
    adapter = pydantic.TypeAdapter(ClaimRequest[int])
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python({'values': ['foo']})


def test_values_can_not_be_empty():
    adapter = pydantic.TypeAdapter(ClaimRequest[int])
    with pytest.raises(pydantic.ValidationError):
        adapter.validate_python({'values': []})


def test_values_can_be_none():
    adapter = pydantic.TypeAdapter(ClaimRequest[int])
    adapter.validate_python({'values': None})


def test_values_can_be_omitted():
    adapter = pydantic.TypeAdapter(ClaimRequest[int])
    adapter.validate_python({})


def test_voluntary_serializes_to_none():
    c = ClaimRequest[str].model_validate({'essential': False})
    assert c.serialize() is None