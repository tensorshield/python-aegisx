import urllib.parse

from aegisx.ext.oauth.models import OIDCClaimSpec


def test_urlencode():
    spec = OIDCClaimSpec.model_validate({
        'id_token': {
            'sub': {
                'essential': True
            },
            'given_name': {
                'essential': True,
                'values': ["Immortal Izzy"]
            }
        }
    })
    data = spec.model_dump(mode='query')
    assert isinstance(data, str)
    decoded = OIDCClaimSpec.model_validate(urllib.parse.unquote_plus(data))
    assert decoded == spec


def test_json_encode():
    spec = OIDCClaimSpec.model_validate({
        'id_token': {
            'sub': {
                'essential': True
            },
            'given_name': {
                'essential': True,
                'values': ["Immortal Izzy"]
            }
        }
    })
    data = spec.model_dump(mode='json')
    assert isinstance(data, dict)


def test_standard_encode():
    spec = OIDCClaimSpec.model_validate({
        'id_token': {
            'sub': {
                'essential': True
            },
            'given_name': {
                'essential': True,
                'values': ["Immortal Izzy"]
            }
        }
    })
    data = spec.model_dump()
    assert isinstance(data, dict)