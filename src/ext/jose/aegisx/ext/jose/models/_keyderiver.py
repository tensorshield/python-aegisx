import struct
from typing import cast
from typing import Any
from typing import Union
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from libcanonical.types import AwaitableBytes
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
if TYPE_CHECKING:
    from ._jsonwebkey import JSONWebKey


SUPPORTED_PRIVATE_KEYS = (
    ec.EllipticCurvePrivateKey,
    x448.X448PrivateKey,
    x25519.X25519PrivateKey
)

SUPPORTED_PUBLIC_KEYS = (
    ec.EllipticCurvePublicKey,
    x448.X448PublicKey,
    x25519.X25519PublicKey
)


class KeyDeriver:

    def derive(
        self,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        private: Union['JSONWebKey', Any],
        public: Union['JSONWebKey', Any],
        apu: bytes,
        apv: bytes,
        ct: EncryptionResult | None = None
    ) -> bytes:
        if not isinstance(private, SUPPORTED_PRIVATE_KEYS):
            private = cast(Any, private.root.private_key) # type: ignore
        if not isinstance(public, SUPPORTED_PUBLIC_KEYS):
            public = cast(Any, public.root.public_key) # type: ignore
        length = enc.length if alg.is_direct() else alg.length
        cipher = enc.cipher if alg.is_direct() else alg.cipher
        if not length:
            raise ValueError(
                f"Unable to determine key size from management algorithm {alg} "
                f"and content encryption algorithm {enc}."
            )
        # The AlgorithmID value is of the form Datalen || Data, where Data is a
        # variable-length string of zero or more octets, and Datalen is a fixed-length,
        # big-endian 32-bit counter that indicates the length (in octets) of Data.
        # In the Direct Key Agreement case, Data is set to the octets of the ASCII
        # representation of the "enc" Header Parameter value.  In the Key Agreement
        # with Key Wrapping case, Data is set to the octets of the ASCII representation
        # of the "alg" (algorithm) Header Parameter value.
        algorithm_id = enc if alg.is_direct() else alg
        otherinfo = struct.pack('>I', len(algorithm_id))
        otherinfo += str.encode(algorithm_id, 'utf-8')

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
        if isinstance(private, ec.EllipticCurvePrivateKey): # type: ignore
            assert isinstance(public, ec.EllipticCurvePublicKey)
            shared_key = private.exchange(ec.ECDH(), public)
        else:
            assert isinstance(private, (x448.X448PrivateKey, x25519.X25519PrivateKey))
            assert isinstance(public, (x448.X448PublicKey, x25519.X25519PublicKey))
            shared_key = private.exchange(public) # type: ignore

        # TODO: abstract this
        keysize = length // 8
        if cipher == 'AES+CBC':
            # In CBC mode, the derived key must be twice the length
            # of the algorithm as the first half is used as the MAC
            # key.
            keysize *= 2

        # RFC 7518 4.6.2: Key derivation is performed using the Concat KDF,
        # as defined in Section 5.8.1 of [NIST.800-56A], where the Digest
        # Method is SHA-256.
        ckdf = ConcatKDFHash(algorithm=SHA256(),
            length=keysize,
            otherinfo=otherinfo,
        )
        k = AwaitableBytes(ckdf.derive(shared_key))
        return k