from typing import overload
from typing import Literal
from typing import Union
from typing import TYPE_CHECKING

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from aegisx.types import SymmetricEncryptionKey
from ._encryptionalgorithm import EncryptionAlgorithm
if TYPE_CHECKING:
    from aegisx.core.crypto import Algorithm


class ECDHEncryptionAlgorithm(EncryptionAlgorithm):
    model_config = {'populate_by_name': True}
    __supported_key_types__ = {'OKP', 'EC'}

    kdf: Literal['NIST-800-56-Concatenation-KDF'] = pydantic.Field(
        default=...
    )

    wrp: Union['Algorithm', None] = pydantic.Field(
        default=None
    )

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
        if isinstance(key, (X448PrivateKey, X448PublicKey)):
            return X448PrivateKey.generate()
        elif isinstance(key, (X25519PrivateKey, X25519PublicKey)):
            return X25519PrivateKey.generate()
        else:
            return generate_private_key(key.curve)

    def derive(
        self,
        private: EllipticCurvePrivateKey | X448PrivateKey | X25519PrivateKey,
        public: EllipticCurvePublicKey | X448PublicKey | X25519PublicKey,
        otherinfo: bytes,
        length: int | None = None
    ) -> SymmetricEncryptionKey:
        if self.wrp:
            length = self.wrp.key_length
        assert length is not None
        if isinstance(private, EllipticCurvePrivateKey):
            assert isinstance(public, EllipticCurvePublicKey)
            shared_key = private.exchange(ECDH(), public)
        else:
            shared_key = private.exchange(public) # type: ignore
        kdf = ConcatKDFHash(
            algorithm=SHA256(),
            length=length // 8,
            otherinfo=otherinfo,
        )
        return SymmetricEncryptionKey(kdf.derive(shared_key))