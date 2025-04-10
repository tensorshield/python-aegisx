import pydantic

from ._jsonwebkey import JSONWebKey
from ._jsonwebkeyset import JSONWebKeySet


class JSONPublicWebKeySet(JSONWebKeySet):
    """Like :class:`JSONWebKeySet`, but it can only contain public
    keys.
    """
    model_config = {'extra': 'forbid'}

    @pydantic.field_validator('keys', mode='after')
    def validate_keys(cls, keys: list[JSONWebKey]):
        if not all([jwk.is_public() for jwk in keys]):
            raise ValueError("private or symmetric keys are not allowed.")
        return keys