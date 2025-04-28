import pathlib
from typing import cast
from typing import overload
from typing import Any
from typing import ClassVar
from typing import Union

import pydantic
import yaml
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from aegisx.types import DigestAlgorithm
from aegisx.types import EncryptionResult
from aegisx.types import SymmetricEncryptionKey
from ._aescbcencryptionalgorithm import AESCBCEncryptionAlgorithm
from ._aesgcmwrapencryptionalgorithm import AESGCMWrapEncryptionAlgorithm
from ._aeskeywrapencryptionalgorithm import AESKeyWrapEncryptionAlgorithm
from ._ecdsasigningalgorithm import ECDSASigningAlgorithm
from ._ecdhencryptionalgorithm import ECDHEncryptionAlgorithm
from ._eddsasigningalgorithm import EdDSASigningAlgorithm
from ._hmacsigningalgorithm import HMACSigningAlgorithm
from ._rsaencryptionalgorithm import RSAEncryptionAlgorithm
from ._rsasigningalgorithm import RSASigningAlgorithm
from ._srdsasigningalgorithm import SrDSASigningAlgorithm


DEFAULT_ALGORITHM_SPEC = pathlib.Path(__file__).parent.joinpath('algorithms.yaml')


class Algorithm(
    pydantic.RootModel[
        Union[
            AESCBCEncryptionAlgorithm,
            AESGCMWrapEncryptionAlgorithm,
            AESKeyWrapEncryptionAlgorithm,
            ECDSASigningAlgorithm,
            ECDHEncryptionAlgorithm,
            EdDSASigningAlgorithm,
            HMACSigningAlgorithm,
            RSASigningAlgorithm,
            SrDSASigningAlgorithm,
            RSAEncryptionAlgorithm,
        ]
    ]
):
    __registry__: ClassVar[dict[str, Any]] = {}

    @property
    def dig(self) -> DigestAlgorithm | None:
        return getattr(self.root, 'dig', None)

    @property
    def key_length(self) -> int | None:
        return getattr(self.root, 'key_length', None)

    @property
    def wrp(self) -> Union['Algorithm', None]:
        return getattr(self.root, 'wrp', None)

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
    @classmethod
    def preprocess(cls, values: Union[dict[str, Any], str, 'Algorithm']):
        name = None
        if isinstance(values, str):
            name = values
        if isinstance(values, dict):
            name = values.get('name')
        elif isinstance(values, cls):
            assert isinstance(values, cls)
            name = values.root.name
        if name:
            name = str(name)
        if name:
            if name not in cls.__registry__:
                raise ValueError(f'Unknown algorithm: {name}')
            values = cls.__registry__[str(name)]
        return values

    def decrypt(self, key: Any, result: EncryptionResult) -> bytes:
        return self.root.decrypt(key, result)

    def derive(self, *args: Any, **kwargs: Any) -> SymmetricEncryptionKey:
        return self.root.derive(*args, **kwargs)

    def encrypt(
        self,
        key: Any,
        plaintext: bytes,
        aad: bytes | None = None
    ) -> EncryptionResult:
        if aad is not None and not self.root.__supports_aad__:
            raise TypeError(
                f'Algorithm {type(self.root).__name__} does not support '
                'Authenticated Additional Data (AAD).'
            )
        return self.root.encrypt(key, plaintext)


    @overload
    def epk(
        self,
        key: X25519PrivateKey | X25519PublicKey
    ) -> X25519PrivateKey:
        ...

    @overload
    def epk(
        self,
        key: X448PrivateKey | X448PublicKey
    ) -> X448PrivateKey:
        ...

    @overload
    def epk(
        self,
        key: EllipticCurvePrivateKey | EllipticCurvePublicKey
    ) -> EllipticCurvePrivateKey:
        ...

    def epk(
        self,
        key: Union[
            EllipticCurvePrivateKey,
            EllipticCurvePublicKey,
            X448PrivateKey,
            X448PublicKey,
            X25519PrivateKey,
            X25519PublicKey
        ]
    ):
        return self.root.epk(key)

    def generate(self) -> Any:
        return self.root.generate()

    def sign(
        self,
        key: Any,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        return self.root.sign(key, message, prehashed)

    def verify(
        self,
        key: Any,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        return self.root.verify(key, signature, message, prehashed)

    def __repr__(self):
        return f'Algorithm(kty="{self.root.kty}", use="{self.root.use}")'


Algorithm.load_defaults()