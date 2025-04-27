import pathlib
from typing import cast
from typing import Any
from typing import ClassVar
from typing import Union

import pydantic
import yaml

from ._ecdsasigningalgorithm import ECDSASigningAlgorithm
from ._eddsasigningalgorithm import EdDSASigningAlgorithm
from ._hmacsigningalgorithm import HMACSigningAlgorithm
from ._rsasigningalgorithm import RSASigningAlgorithm
from ._srdsasigningalgorithm import SrDSASigningAlgorithm


DEFAULT_ALGORITHM_SPEC = pathlib.Path(__file__).parent.joinpath('algorithms.yaml')


class Algorithm(
    pydantic.RootModel[
        Union[
            ECDSASigningAlgorithm,
            EdDSASigningAlgorithm,
            HMACSigningAlgorithm,
            RSASigningAlgorithm,
            SrDSASigningAlgorithm
        ]
    ]
):
    __registry__: ClassVar[dict[str, Any]] = {}

    @classmethod
    def load_defaults(cls, defaults: pathlib.Path = DEFAULT_ALGORITHM_SPEC):
        if cls.__registry__:
            return
        with open(defaults, 'r') as f:
            data = cast(dict[str, Any], yaml.safe_load(f.read()))
        for name, params in data.items():
            cls.__registry__[name] = {
                **cls.model_validate(params).model_dump(
                    exclude_none=True,
                    exclude_unset=True
                ),
                'name': name
            }

    @pydantic.model_validator(mode='before')
    def preprocess(cls, values: Union[dict[str, Any], 'Algorithm']):
        name = None
        if isinstance(values, dict):
            name = values.get('name')
        elif isinstance(values, cls): # type: ignore
            name = values.root.name
        if name:
            name = str(name)
        if name:
            if name not in cls.__registry__:
                raise ValueError(f'Unknown algorithm: {name}')
            values = cls.__registry__[str(name)]
        return values

    def __repr__(self):
        return f'Algorithm(kty="{self.root.kty}", use="{self.root.use}")'


Algorithm.load_defaults()