from typing import Any

import pytest

from aegisx.ext.oauth.models import ClaimRequest
from aegisx.ext.oauth.models import RequestedClaims


def test_null_values_are_validated_as_claimrequests():
    requested = RequestedClaims.model_validate({
        'given_name': None
    })
    assert requested.__pydantic_extra__ is not None
    assert isinstance(requested.__pydantic_extra__.get('given_name'), ClaimRequest)


@pytest.mark.parametrize("obj", [
    {'auth_time': {'essential': True}},
    {'sub': {'value': '248289761001'}},
    {'acr': {'essential': True, 'values': ['urn:mace:incommon:iap:silver', 'urn:mace:incommon:iap:bronze']}}
])
def test_specification_examples(obj: dict[str, Any]):
    requested = RequestedClaims.model_validate(obj)
    for key, value in obj.items():
        assert key in requested.__pydantic_extra__
        assert isinstance(requested.__pydantic_extra__[key], ClaimRequest)
        assert value.get('essential', False) == requested.__pydantic_extra__[key].essential
        if value.get('value'):
            assert requested.__pydantic_extra__[key].values == [value['value']]
        if value.get('values'):
            assert requested.__pydantic_extra__[key].values == value['values']