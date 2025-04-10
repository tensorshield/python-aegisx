from typing import cast
from typing import Any
from typing import Literal
from typing import Union
from typing import TYPE_CHECKING

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from libcanonical.types import AwaitableBool
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeybase import JSONWebKeyBase
from ._keyderiver import KeyDeriver
from ._symmetricencryptionkey import SymmetricEncryptionKey
if TYPE_CHECKING:
    from ._jsonwebkey import JSONWebKey


class JSONWebKeyEdwardsCurvePublic(
    JSONWebKeyBase[
        Literal['OKP'],
        Literal['sign', 'verify', 'wrapKey', 'unwrapKey']
    ],
    KeyDeriver
):
    model_config = {
        'title': 'EdDSA Public Key'
    }


    thumbprint_claims = ["crv", "kty", "x"]

    crv: Literal['Ed25519', 'X25519', 'Ed448', 'X448'] = pydantic.Field(
        default=...,
        title="Curve",
        description=(
            "The `crv` (curve) parameter identifies the "
            "cryptographic curve used with the key."
        )
    )

    x: Base64 = pydantic.Field(
        default=...,
        title="Public key",
        description=(
            "Contains the public key encoded using the base64url encoding."
        )
    )

    @property
    def public_key(self):
        match self.crv:
            case 'Ed448':
                return Ed448PublicKey.from_public_bytes(self.x)
            case 'Ed25519':
                return Ed25519PublicKey.from_public_bytes(self.x)
            case 'X448':
                return X448PublicKey.from_public_bytes(self.x)
            case 'X25519':
                return X25519PublicKey.from_public_bytes(self.x)

    @pydantic.model_validator(mode='before')
    def preprocess(cls, value: dict[str, Any] | Any):
        if isinstance(value, dict):
            value = cast(dict[str, Any], value)
            if value.get('kty') == 'OKP' and value.get('public_bytes')\
            and value.get('crv') in {'Ed448', 'Ed25519', 'X448', 'X25519'}:
                value['x'] = Base64(value.pop('public_bytes'))
        return value

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return alg.config.name == 'EdDSA' or all([
            alg.use == 'enc',
            str.startswith(alg, 'ECDH-ES')
        ])

    def get_public_bytes(self) -> Any:
        return self.public_key.public_bytes_raw()

    def get_public_key(self) -> Any:
        return JSONWebKeyEdwardsCurvePublic.model_validate({
            **self.model_dump(exclude={'d'}),
            'key_ops': (self.key_ops & {'verify', 'encrypt', 'wrapKey'}) if self.key_ops else None
        })

    def is_asymmetric(self) -> bool:
        return True

    def derive_cek(
        self,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        private: Union['JSONWebKey', X448PrivateKey | X25519PrivateKey],
        public: Union['JSONWebKey', X448PublicKey | X25519PublicKey],
        apu: bytes,
        apv: bytes,
        ct: EncryptionResult | None = None
    ) -> SymmetricEncryptionKey:
        shared = self.derive(alg, enc, private, public, apu, apv, ct)
        return SymmetricEncryptionKey(
            alg=alg.wrap if not alg.is_direct() else enc,
            kty='oct',
            k=Base64(shared)
        )

    def epk(self) -> tuple['JSONWebKeyEdwardsCurvePublic', X448PrivateKey|X25519PrivateKey]:
        match self.crv:
            case 'X448':
                private = X448PrivateKey.generate()
            case 'X25519':
                private = X25519PrivateKey.generate()
            case _:
                raise ValueError(
                    f"Can not create an ephemeral keypair with curve {self.crv}"
                )
        return (
            JSONWebKeyEdwardsCurvePublic.model_validate({
                **self.model_dump(include={'kty', 'crv'}),
                'x': Base64(private.public_key().public_bytes_raw()),
            }),
            private
        )

    def encrypt(
        self,
        pt: bytes,
        aad: bytes | None,
        alg: JSONWebAlgorithm
    ) -> EncryptionResult:
        if not alg.length:
            raise ValueError(f"Algorithm {alg} does not specify key size.")
        if not alg.wrap:
            raise ValueError(f"Algorithm {alg} does not specify a wrapping algorithm.")
        if not isinstance(self.public_key, (X448PublicKey, X25519PublicKey)):
            raise ValueError(
                f"Can not create an ephemeral keypair with curve {self.crv}"
            )
        public, private = self.epk()
        shared = self.derive_cek(alg, alg.wrap, private, self.public_key, b'', b'', None)
        result: EncryptionResult
        match alg.mode:
            case 'KEY_AGREEMENT_WITH_KEY_WRAPPING':
                result = EncryptionResult.model_validate({
                    'alg': alg,
                    'ct': bytes(shared.encrypt(pt)),
                    'epk': public.model_dump()
                })
            case _:
                raise NotImplementedError(f"Unsupported algorithm: {alg}")
        return result

    def verify(
        self,
        signature: bytes,
        message: bytes
    ) -> AwaitableBool:
        assert isinstance(self.public_key, (Ed448PublicKey, Ed25519PublicKey))
        try:
            self.public_key.verify(signature, message)
            return AwaitableBool(True)
        except InvalidSignature:
            return AwaitableBool(False)