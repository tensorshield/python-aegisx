import struct
from typing import cast
from typing import Any

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from libcanonical.types import AwaitableBytes
from libcanonical.utils.encoding import b64encode_int
from libcanonical.utils.encoding import b64decode_int
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.utils import normalize_ec_signature
from ._jsonwebkeyellipticcurvepublic import JSONWebKeyEllipticCurvePublic


class JSONWebKeyEllipticCurvePrivate(JSONWebKeyEllipticCurvePublic):
    model_config = {
        'title': 'Elliptic Curve Private Key'
    }

    d: str = pydantic.Field(
        default=...,
        title="ECC private key",
        description=(
            "The `d` (ECC private key) parameter contains the elliptic "
            "curve private key value. It is represented as the base64url "
            "encoding of the octet string representation of the private "
            "key value, as defined in Section 2.3.7 of SEC1. The length "
            "of this octet string MUST be ceiling(log-base-2(n)/8) octets "
            "(where n is the order of the curve)."
        )
    )

    @property
    def private_numbers(self):
        return EllipticCurvePrivateNumbers(
            public_numbers=self.public_numbers,
            private_value=b64decode_int(self.d)
        )

    @property
    def private_key(self):
        return self.private_numbers.private_key()

    @classmethod
    def generate(
        cls,
        alg: JSONWebAlgorithm,
        crv: str | None = None,
        **kwargs: Any
    ) -> 'JSONWebKeyEllipticCurvePrivate':
        crv = crv or alg.config.crv
        if crv is None:
            raise ValueError(
                f"Algorithm {alg} did not specify a curve. The `crv` "
                "parameter must not be None."
            )
        k = generate_private_key(cls.get_curve(crv))
        n = k.private_numbers()
        return cls.model_validate({
            **kwargs,
            **alg.config.params(),
            'crv': crv,
            'd': b64encode_int(n.private_value),
            'x': b64encode_int(n.public_numbers.x),
            'y': b64encode_int(n.public_numbers.y)
        })

    @pydantic.model_validator(mode='wrap')
    @classmethod
    def preprocess_private_key(
        cls,
        values: dict[str, Any] | None,
        nxt: pydantic.ValidatorFunctionWrapHandler
    ):
        if not isinstance(values, dict):
            return nxt(values)
        if isinstance(values.get('private_key'), EllipticCurvePrivateKey):
            private = cast(EllipticCurvePrivateKey, values.pop('private_key'))
            n = private.private_numbers()
            values.update({
                'kty': 'EC',
                'crv': private.curve.name,
                'd': b64encode_int(n.private_value),
                'x': b64encode_int(n.public_numbers.x),
                'y': b64encode_int(n.public_numbers.y)
            })
        return nxt(values)

    def get_public_key(self):
        return JSONWebKeyEllipticCurvePublic.model_validate({
            **self.model_dump(
                exclude={'d'}
            ),
            'key_ops': (self.key_ops & {'verify', 'encrypt', 'wrapKey'}) if self.key_ops else None
        })

    def decrypt(self, result: EncryptionResult) -> AwaitableBytes:
        assert result.epk is not None
        assert result.alg.config.length
        if not isinstance(result.epk.public_key, EllipticCurvePublicKey):
            raise TypeError(f"Invalid key type for key deriviation: {result.epk.kty}")
        derived = self._derive(
            public_key=result.epk.public_key,
            alg=result.alg,
            length=result.alg.length,
            apu=result.apu,
            apv=result.apv
        )
        match result.alg.config.mode == 'KEY_AGREEMENT_WITH_KEY_WRAPPING':
            case True:
                return AwaitableBytes(aes_key_unwrap(derived, result.ct))
            case False:
                return AwaitableBytes(derived)

    def sign(self, message: bytes, alg: JSONWebAlgorithm | None = None) -> AwaitableBytes:
        alg = alg or self.alg
        if alg is None:
            raise ValueError(f"The `alg` parameter is required.")
        sig = normalize_ec_signature(
            l=(self.public_key.curve.key_size + 7) // 8,
            sig=self.private_key.sign(message, ECDSA(self.get_hash(alg)))
        )
        return AwaitableBytes(sig)

    def _derive(
        self,
        public_key: EllipticCurvePublicKey,
        alg: JSONWebAlgorithm,
        length: int,
        apu: bytes,
        apv: bytes
    ):
        # OtherInfo is defined in NIST SP 56A 5.8.1.2.1

        # AlgorithmID
        otherinfo = struct.pack('>I', len(alg))
        otherinfo += str.encode(alg, 'utf-8')

        # PartyUInfo
        apu = b64decode(apu) if apu else b''
        otherinfo += struct.pack('>I', len(apu))
        otherinfo += apu

        # PartyVInfo
        apv = b64decode(apv) if apv else b''
        otherinfo += struct.pack('>I', len(apv))
        otherinfo += apv

        # SuppPubInfo
        otherinfo += struct.pack('>I', length)

        # Shared Key generation
        if isinstance(self.private_key, EllipticCurvePrivateKey): # type: ignore
            shared_key = self.private_key.exchange(ECDH(), public_key)
        else:
            # X25519/X448
            shared_key = self.private_key.exchange(public_key)

        ckdf = ConcatKDFHash(algorithm=SHA256(),
            length=length//8,
            otherinfo=otherinfo,
        )
        return ckdf.derive(shared_key)