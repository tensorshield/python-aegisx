from typing import cast
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Literal
from typing import TypeVar
from typing import Union
from typing import TYPE_CHECKING

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import Certificate
from libcanonical.types import AwaitableBool
from libcanonical.types import Base64
from libcanonical.utils.encoding import b64decode_int
from libcanonical.utils.encoding import b64encode_int
from libcanonical.utils.encoding import bytes_to_number

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeybase import JSONWebKeyBase
from ._keyderiver import KeyDeriver
from ._symmetricencryptionkey import SymmetricEncryptionKey
if TYPE_CHECKING:
    from ._jsonwebkey import JSONWebKey


R = TypeVar('R')

CURVE_NAMES = {
    'secp256r1': 'P-256'
}

SIGNATURE_ALGORITHM_OID = {
    '1.2.840.10045.4.3.2': 'sha256',
    '1.2.840.10045.4.3.3': 'sha384',
    '1.2.840.10045.4.3.4': 'sha512',
}


class JSONWebKeyEllipticCurvePublic(
    KeyDeriver,
    JSONWebKeyBase[
        Literal['EC'],
        Literal['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    ]
):
    public_key_type: ClassVar[type[EllipticCurvePublicKey]] = EllipticCurvePublicKey
    signing_algorithm_oid: ClassVar[dict[str, str]] = {
        '1.2.840.10045.4.3.2': 'sha256',
        '1.2.840.10045.4.3.3': 'sha384',
        '1.2.840.10045.4.3.4': 'sha512',
    }

    model_config = {
        'title': 'Elliptic Curve Public Key'
    }

    thumbprint_claims = ["crv", "kty", "x", "y"]
    curves: ClassVar[dict[str, type[EllipticCurve]]] = {
        'P-256': SECP256R1,
        'P-256K': SECP256K1,
        'P-384': SECP384R1,
        'P-521': SECP521R1,
    }

    crv: Literal['P-256', 'P-256K', 'P-384', 'P-521'] = pydantic.Field(
        default=...,
        title="Curve",
        description=(
            "The `crv` (curve) parameter identifies the "
            "cryptographic curve used with the key."
        )
    )

    x: str = pydantic.Field(
        default=...,
        title="X coordinate",
        description=(
            "The `x` (x coordinate) parameter contains the x "
            "coordinate for the Elliptic Curve point. It is "
            "represented as the base64url encoding of the octet "
            "string representation of the coordinate, as defined "
            "in Section 2.3.5 of SEC1. The length of this octet "
            "string MUST be the full size of a coordinate for "
            "the curve specified in the `crv` parameter. For "
            "example, if the value of `crv` is `P-521`, the octet "
            "string must be 66 octets long."
        )
    )

    y: str = pydantic.Field(
        default=...,
        title="Y coordinate",
        description=(
            "The `y` (y coordinate) parameter contains the y "
            "coordinate for the Elliptic Curve point. It is "
            "represented as the base64url encoding of the octet "
            "string representation of the coordinate, as defined "
            "in Section 2.3.5 of SEC1. The length of this octet "
            "string MUST be the full size of a coordinate for "
            "the curve specified in the `crv` parameter. For "
            "example, if the value of `crv` is `P-521`, the "
            "octet string must be 66 octets long."
        )
    )

    @property
    def public_numbers(self) -> EllipticCurvePublicNumbers:
        return EllipticCurvePublicNumbers(
            curve=self.get_curve(self.crv),
            x=b64decode_int(self.x),
            y=b64decode_int(self.y)
        )

    @property
    def public_key(self):
        return self.public_numbers.public_key()

    @classmethod
    def get_curve(cls, crv: str):
        return cls.curves[crv]()

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return alg.config.kty == 'EC'

    @pydantic.model_validator(mode='before')
    def preprocess_certificate(
        cls,
        values: Any | dict[str, Any]
    ):
        if isinstance(values, dict):
            values = cast(dict[str, Any], values)
            crt: Any = cast(Any, values.get('crt'))
            if crt is not None:
                if not isinstance(crt, Certificate):
                    raise TypeError(
                        'The "crt" parameter must be an instance of '
                        'cryptography.x509.Certificate.'
                    )
                public = crt.public_key()
                if not isinstance(public, cls.public_key_type):
                    raise TypeError(
                        'The certificate public key must be an instance '
                        f'of {cls.public_key_type.__name__}'
                    )
                signature_oid = crt.signature_algorithm_oid.dotted_string
                if signature_oid not in cls.signing_algorithm_oid:
                    raise ValueError(
                        f'Unsupported signature algorithm: {signature_oid}'
                    )
                if not crt.signature_hash_algorithm:
                    raise ValueError(f'Unhashed signatures are not supported.')
                digest_name = crt.signature_hash_algorithm.name
                if digest_name not in {'sha256', 'sha384', 'sha512'}:
                    raise ValueError(f'Unsupported digest algorithm: {digest_name}')
                values.update({
                    'kty': 'EC',
                    'use': 'sig',
                    'key_ops': {'verify'},
                    'crv': CURVE_NAMES[public.curve.name],
                    'x': b64encode_int(public.public_numbers().x),
                    'y': b64encode_int(public.public_numbers().y)
                })
        return values

    @pydantic.field_validator('crv', mode='before')
    def preprocess_crv(cls, value: str) -> str:
        if value in CURVE_NAMES:
            value = CURVE_NAMES[value]
        return value

    def epk(self) -> tuple['JSONWebKeyEllipticCurvePublic', EllipticCurvePrivateKey]:
        private = generate_private_key(self.public_numbers.curve)
        n = private.private_numbers()
        return (
            JSONWebKeyEllipticCurvePublic.model_validate({
                **self.model_dump(include={'kty', 'crv'}),
                'x': b64encode_int(n.public_numbers.x),
                'y': b64encode_int(n.public_numbers.y)
            }),
            private
        )

    def exchange(self, f: Callable[[Any], R]) -> R:
        return f(self.public_key)

    def get_public_key(self):
        return JSONWebKeyEllipticCurvePublic.model_validate(self.model_dump())

    def is_asymmetric(self) -> bool:
        return True

    def derive_cek(
        self,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        private: Union['JSONWebKey', EllipticCurvePrivateKey],
        public: Union['JSONWebKey', EllipticCurvePublicKey],
        apu: bytes,
        apv: bytes,
        ct: EncryptionResult | None = None
    ) -> SymmetricEncryptionKey:
        # TODO: ugly, refactor
        if not isinstance(public, EllipticCurvePublicKey):
            if isinstance(public.root, JSONWebKeyEllipticCurvePublic):
                public = public.root.public_key
        if not isinstance(public, EllipticCurvePublicKey):
            raise TypeError(
                "A key can only be derived using an elliptic curve "
                "public key."
            )
        shared = self.derive(alg, enc, private, public, apu, apv, ct)
        return SymmetricEncryptionKey(
            alg=alg.wrap if not alg.is_direct() else enc,
            kty='oct',
            k=Base64(shared)
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
        assert self.alg is not None
        n = (self.public_key.curve.key_size + 7) // 8
        try:
            self.public_key.verify(
                signature=encode_dss_signature(
                    bytes_to_number(signature[:n]),
                    bytes_to_number(signature[n:]),
                ),
                data=message,
                signature_algorithm=ECDSA(self.get_hash(self.alg))
            )
            return AwaitableBool(True)
        except InvalidSignature:
            return AwaitableBool(False)