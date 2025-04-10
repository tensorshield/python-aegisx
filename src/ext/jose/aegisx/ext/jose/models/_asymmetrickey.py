from typing import Generic
from typing import Literal
from typing import TypeVar

from aegisx.ext.jose.types import KeyOperationType
from aegisx.ext.jose.types import KeyUseType
from ._jsonwebkeybase import JSONWebKeyBase


K = TypeVar('K')
O = TypeVar('O', bound=KeyOperationType)
U = TypeVar('U', bound=KeyUseType, default=Literal['sig', 'enc'])


class AsymmetricKey(JSONWebKeyBase[K, O, U], Generic[K, O, U]): # pragma: no cover
    model_config = {'extra': 'forbid', 'populate_by_name': True}

    def is_asymmetric(self) -> bool:
        return True