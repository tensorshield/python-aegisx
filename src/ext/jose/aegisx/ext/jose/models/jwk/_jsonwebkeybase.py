import datetime
import hashlib
import logging
import time
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Generic
from typing import Literal
from typing import TypeVar

import pydantic
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.hashes import SHA512
from libcanonical.types import AwaitableBool
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64
from libcanonical.types import Base64URLEncoded
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import KeyOperationType
from aegisx.ext.jose.types import KeyUseType
from aegisx.ext.jose.types import ThumbprintHashAlgorithm


K = TypeVar('K')
O = TypeVar('O', bound=KeyOperationType)
U = TypeVar('U', bound=KeyUseType, default=Literal['sig', 'enc'])
R = TypeVar('R')


class JSONWebKeyBase(pydantic.BaseModel, Generic[K, O, U]): # pragma: no cover
    logger: ClassVar[logging.Logger] = logging.getLogger(__name__) 
    model_config = {
        'extra': 'ignore',
        'populate_by_name': True,
    }
    thumbprint_claims: ClassVar[list[str]]

    hashes: ClassVar[dict[str, type[HashAlgorithm]]] = {
        'sha256': SHA256,
        'sha384': SHA384,
        'sha512': SHA512
    }

    kty: K = pydantic.Field(
        default=...,
        title="Key type",
        description=(
            "The `kty` (key type) parameter identifies the cryptographic algorithm "
            "family used with the key, such as `RSA` or `EC`.  `kty` values should "
            "either be registered in the IANA _JSON Web Key Types_ registry "
            "or be a value that contains a Collision-Resistant Name. The `kty` "
            "value is a case-sensitive string. This member MUST be present in "
            "a JWK."
        )
    )

    use: U | None = pydantic.Field(
        default=None,
        title="Use",
        description=(
            "The `use` (public key use) parameter identifies the intended use of "
            "the public key. The `use` parameter is employed to indicate whether "
            "a public key is used for encrypting data or verifying the signature "
            "on data."
        )
    )

    key_ops: set[O] = pydantic.Field(
        default_factory=set,
        title="Key operations",
        description=(
            "The `key_ops` (key operations) parameter identifies the operation(s) "
            "for which the key is intended to be used. The `key_ops` parameter is "
            "intended for use cases in which public, private, or symmetric keys "
            "may be present."
        )
    )

    kid: str | None = pydantic.Field(
        default=None,
        title="Key ID",
        description=(
            "The `kid` (key ID) parameter is used to match a specific key.  "
            "This is used, for instance, to choose among a set of keys within "
            "a JWK Set during key rollover. The structure of the `kid` value "
            "is unspecified. When `kid` values are used within a JWK Set, "
            "different keys within the JWK Set SHOULD use distinct `kid` "
            "values. (One example in which different keys might use the same "
            "`kid` value is if they have different `kty` (key type) values "
            "but are considered to be equivalent alternatives by the "
            "application using them.) The `kid` value is a case-sensitive "
            "string.  Use of this member is OPTIONAL. When used with JWS "
            "or JWE, the `kid` value is used to match a JWS or JWE `kid` "
            "Header Parameter value."
        )
    )

    alg: JSONWebAlgorithm | None = pydantic.Field(
        default=None,
        title="Algorithm",
        description=(
            "The `alg` (algorithm) parameter identifies the algorithm intended "
            "for use with the key.  The values used should either be registered "
            "in the IANA _JSON Web Signature and Encryption Algorithms_ registry "
            "or be a value that contains a Collision-Resistant Name.  The `alg` "
            "value is a case-sensitive ASCII string. Use of this member is "
            "OPTIONAL."
        )
    )

    x5u: HTTPResourceLocator | None = pydantic.Field(
        default=None,
        title="X.509 URL",
        description=(
            "The `x5u` (X.509 URL) parameter is a URI [RFC3986] that refers to a "
            "resource for an X.509 public key certificate or certificate chain. "
            "The identified resource MUST provide a representation of the certificate "
            "or certificate chain that conforms to RFC 5280 in PEM-encoded form,"
            "with each certificate delimited as specified in Section 6.1 of RFC "
            "4945.  The key in the first certificate MUST match the public key "
            "represented by other members of the JWK. The protocol used to acquire "
            "the resource MUST provide integrity protection; an HTTP GET request "
            "to retrieve the certificate MUST use TLS as defined in RFC2818, RFC5246; "
            "the identity of the server MUST be validated, as per Section 6 of RFC "
            "6125.  Use of this member is OPTIONAL."
        )
    )

    x5c: list[Base64] | None = pydantic.Field(
        default=None,
        title="X.509 Certificate Chain",
        description=(
            "The `x5c` (X.509 certificate chain) parameter contains a chain of "
            "one or more PKIX certificates (RFC5280).  The certificate chain "
            "is represented as a JSON array of certificate value strings. "
            "Each string in the array is a base64-encoded (Section 4 of [RFC4648] "
            "-- not base64url-encoded) DER (ITU.X690.1994) PKIX certificate "
            "value. The PKIX certificate containing the key value MUST be the "
            "first certificate. This MAY be followed by additional certificates, "
            "with each subsequent certificate being the one used to certify "
            "the previous one. The key in the first certificate MUST match "
            "the public key represented by other members of the JWK. "
            "Use of this member is OPTIONAL."
        )
    )

    x5t: Base64URLEncoded | None = pydantic.Field(
        default=None,
        title="X.509 Certificate SHA-1 Thumbprint",
        description=(
            "The `x5t` (X.509 certificate SHA-1 thumbprint) parameter is a "
            "base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER "
            "encoding of an X.509 certificate (RFC5280). Note that certificate "
            "thumbprints are also sometimes known as certificate fingerprints. "
            "The key in the certificate MUST match the public key represented "
            "by other members of the JWK.  Use of this member is OPTIONAL."
        ),
        min_length=20,
        max_length=20
    )

    x5t_s256: Base64URLEncoded | None = pydantic.Field(
        default=None,
        title="X.509 Certificate SHA-256 Thumbprint",
        description=(
            "The `x5t#S256` (X.509 certificate SHA-256 thumbprint) parameter "
            "is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the "
            "DER encoding of an X.509 certificate (RFC5280). Note that "
            "certificate thumbprints are also sometimes known as certificate "
            "fingerprints. The key in the certificate MUST match the public "
            "key represented by other members of the JWK.  Use of this member "
            "is OPTIONAL."
        ),
        alias='x5t#S256'
    )

    exp: int | None = pydantic.Field(
        default=None,
        title="Expires",
        description=(
            "The `exp` (expiration time) claim identifies the expiration "
            "time on or after which the JWK MUST NOT be accepted for "
            "processing. The processing of the `exp` claim requires "
            "that the current date/time MUST be before the expiration "
            "date/time listed in the `exp` claim. Implementers MAY "
            "provide for some small leeway, usually no more than a "
            "few minutes, to account for clock skew.  Its value MUST "
            "be a number containing a `NumericDate` value.  Use of this "
            "claim is OPTIONAL."
        )
    )

    nbf: int | None = pydantic.Field(
        default=None,
        title="Not before",
        description=(
            "The `nbf` (not before) claim identifies the time before which "
            "the JWT MUST NOT be accepted for processing.  The processing "
            "of the `nbf` claim requires that the current date/time MUST "
            "be after or equal to the not-before date/time listed in the "
            "`nbf` claim. Implementers MAY provide for some small leeway, "
            "usually no more than a few minutes, to account for clock skew. "
            "Its value MUST be a number containing a `NumericDate` value. "
            "Use of this claim is OPTIONAL."
        )
    )

    iat: int | None = pydantic.Field(
        default=None,
        title="Issued at",
        description=(
            "The `iat` (issued at) claim identifies the time at which "
            "the JWK was issued. This claim can be used to determine "
            "the age of the JWK. Its value MUST be a number containing "
            "a `NumericDate` value. Use of this claim is OPTIONAL."
        )
    )

    @property
    def public(self):
        return self.get_public_key()

    @property
    def public_bytes(self):
        return self.get_public_bytes()

    @classmethod
    def supports_algorithm(cls, alg: JSONWebAlgorithm) -> bool:
        return False

    @pydantic.field_validator('exp', mode='before')
    def validate_exp(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now') or int(time.time())
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize' and value is not None:
                if value < now:
                    raise ValueError(f'key expired at {dt}')
        return value

    @pydantic.field_validator('nbf', mode='before')
    def validate_nbf(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now') or int(time.time())
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize' and value is not None:
                if value > now:
                    raise ValueError(f'key must not be used before {dt}')
        return value

    def decrypt(self, result: EncryptionResult) -> Any:
        raise NotImplementedError

    def derive_cek(
        self,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        private: Any,
        public: Any,
        apu: bytes,
        apv: bytes,
        ct: EncryptionResult | None = None
    ) -> Any:
        raise NotImplementedError

    def encrypt(
        self,
        pt: bytes,
        aad: bytes | None,
        alg: JSONWebAlgorithm
    ) -> EncryptionResult:
        raise NotImplementedError

    def epk(self) -> tuple[Any, Any]:
        """Create an ephemeral keypair to use in a key exchange."""
        raise NotImplementedError

    def exchange(self, f: Callable[[Any], R]) -> R:
        """Perform a key exchange and return the shared secret. Callable
        `f` accepts a single positional argument, which is the public
        key.
        """
        raise NotImplementedError

    def get_hash(self, alg: JSONWebAlgorithm):
        if alg.config.dig is None:
            raise ValueError(f"Algorithm {alg} does not specify a hash algorithm.")
        return self.hashes[alg.config.dig]()

    def get_public_bytes(self) -> Any:
        raise NotImplementedError

    def get_public_key(self) -> Any:
        raise NotImplementedError

    def is_asymmetric(self) -> bool:
        raise NotImplementedError

    def is_private(self) -> bool:
        return True

    def sign(self, message: bytes, alg: JSONWebAlgorithm | None = None) -> AwaitableBytes:
        raise NotImplementedError

    def thumbprint(
        self,
        using: ThumbprintHashAlgorithm = 'sha256'
    ) -> str:
        claims = self.model_dump(mode='json', exclude_none=True)
        h = hashlib.new(using)
        for name in self.thumbprint_claims:
            h.update(str.encode(claims[name], 'utf-8'))
        return b64encode(h.digest(), encoder=str)

    def verify(
        self,
        signature: bytes,
        message: bytes
    ) -> AwaitableBool:
        raise NotImplementedError

    def __bytes__(self) -> bytes:
        raise NotImplementedError