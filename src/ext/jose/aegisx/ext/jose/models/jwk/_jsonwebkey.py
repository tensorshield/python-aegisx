import time
from typing import overload
from typing import Any
from typing import Literal
from typing import TypeVar
from typing import Union

import pydantic
from libcanonical.types import AwaitableBytes

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JOSEHeaderDict
from aegisx.ext.jose.types import ThumbprintHashAlgorithm
from ._jsonwebkeyedwardscurveprivate import JSONWebKeyEdwardsCurvePrivate
from ._jsonwebkeyedwardscurvepublic import JSONWebKeyEdwardsCurvePublic
from ._jsonwebkeyellipticcurveprivate import JSONWebKeyEllipticCurvePrivate
from ._jsonwebkeyellipticcurveprivate import JSONWebKeyEllipticCurvePublic
from ._jsonwebkeyrsaprivate import JSONKeyRSAPrivate
from ._jsonwebkeyrsapublic import JSONKeyRSAPublic
from ._jsonwebkeysr25519private import JSONWebKeySR25519Private
from ._jsonwebkeysr25519public import JSONWebKeySR25519Public
from ._symmetricencryptionkey import SymmetricEncryptionKey
from ._symmetricsigningkey import SymmetricSigningKey


__all__: list[str] = [
    'JSONWebKey'
]

R = TypeVar('R')

JSONWebKeyType = Union[
    JSONWebKeyEdwardsCurvePrivate,
    JSONWebKeyEllipticCurvePrivate,
    JSONKeyRSAPrivate,
    JSONWebKeySR25519Private,
    JSONWebKeyEdwardsCurvePublic,
    JSONWebKeyEllipticCurvePublic,
    JSONKeyRSAPublic,
    JSONWebKeySR25519Public,
    SymmetricEncryptionKey,
    SymmetricSigningKey
]

PUBLIC_KEY_TYPES = (
    #JSONWebKeySR25519Public,
    JSONKeyRSAPublic,
    JSONWebKeyEdwardsCurvePublic,
    JSONWebKeyEllipticCurvePublic
)


class JSONWebKey(pydantic.RootModel[JSONWebKeyType]):

    @property
    def alg(self): # pragma: no cover
        return self.root.alg

    @property
    def crv(self): # pragma: no cover
        return self.root.crv

    @property
    def exp(self):
        return self.root.exp

    @property
    def kid(self) -> str | None: # pragma: no cover
        return self.root.kid

    @property
    def key_ops(self): # pragma: no cover
        return self.root.key_ops

    @property
    def kty(self): # pragma: no cover
        return self.root.kty

    @property
    def nbf(self):
        return self.root.nbf

    @property
    def public(self) -> Union['JSONWebKey', None]: # pragma: no cover
        key = None
        if self.is_asymmetric():
            key = JSONWebKey(root=self.root.public)
        return key

    @property
    def public_bytes(self):
        assert isinstance(self.root, PUBLIC_KEY_TYPES)
        return self.root.public_bytes

    @property
    def public_key(self):
        assert isinstance(self.root, PUBLIC_KEY_TYPES)
        return self.root.public_key

    @property
    def use(self): # pragma: no cover
        return self.root.use

    @property
    def x5t(self):
        return self.root.x5t

    @property
    def x5t_s256(self):
        return self.root.x5t_s256

    @classmethod
    def cek(cls, alg: JSONWebAlgorithm, enc: JSONWebAlgorithm):
        # TODO: Abstract all algorithms to a common Algorithm registry.
        length = None
        if enc.cipher == 'AES+CBC':
            length = enc.length * 2
        return cls.generate(alg=enc, length=length)

    @overload
    @classmethod
    def generate(
        cls,
        alg: JSONWebAlgorithm | str,
        **kwargs: Any
    ) -> 'JSONWebKey':  # pragma: no cover
        ...

    @overload
    @classmethod
    def generate(
        cls,
        kty: Literal['RSA'],
        length: int = 4096,
        exponent: int = 65537,
        **kwargs: Any
    ) -> 'JSONWebKey': # pragma: no cover
        ...

    @overload
    @classmethod
    def generate(
        cls,
        alg: Literal['EdDSA'],
        crv: Literal['Ed448', 'Ed25519', 'X448', 'X25519', 'Sr25519'],
        **kwargs: Any
    ) -> 'JSONWebKey': # pragma: no cover
        ...

    @overload
    @classmethod
    def generate(
        cls,
        kty: Literal['EC'],
        crv: str,
        *kwargs: Any
    ) -> 'JSONWebKey': # pragma: no cover
        ...

    @overload
    @classmethod
    def generate(
        cls,
        kty: Literal['OKP'],
        crv: Literal['Ed448', 'Ed25519', 'X448', 'X25519', 'Sr25519']
    ) -> 'JSONWebKey':
        ...

    @classmethod
    def generate(  # type: ignore
        cls,
        kty: Literal['RSA', 'EC', 'OKP', 'oct'] | None = None,
        alg: JSONWebAlgorithm | str | None = None,
        kid: str | None = None,
        **kwargs: Any
    ):
        if not kty and not alg: # pragma: no cover
            raise ValueError("Either the `kty` or `alg` parameter must be specified.")
        if isinstance(alg, str):
            alg = JSONWebAlgorithm.validate(alg)
        root: JSONWebKeyType | None = None
        if alg is not None:
            kty = kty or alg.config.kty
        match kty:
            case 'RSA':
                assert alg is not None
                root = JSONKeyRSAPrivate.generate(alg=alg, **kwargs)
            case 'EC':
                assert alg is not None
                root = JSONWebKeyEllipticCurvePrivate.generate(alg=alg, **kwargs)
            case 'OKP':
                alg = alg or JSONWebAlgorithm.validate('EdDSA')
                match kwargs.get('crv'):
                    case 'Sr25519':
                        root = JSONWebKeySR25519Private.generate(alg=alg)
                    case _: # pragma: no cover
                        root = JSONWebKeyEdwardsCurvePrivate.generate(alg=alg, **kwargs)
            case 'oct':
                assert alg is not None
                match alg.config.use:
                    case 'enc':
                        root = SymmetricEncryptionKey.generate(alg, **kwargs)
                    case 'sig':
                        root = SymmetricSigningKey.generate(alg, length=alg.length)
            case _: # pragma: no cover
                raise ValueError(f"Unsupported algorithm: {alg}")
        assert root is not None
        root.iat = int(time.time())
        if kid is not None:
            root.kid = kid
        return cls(root=root)

    def __init__(self, **kwargs: Any):
        # Only here to suppress type warnings.
        super().__init__(**kwargs) # type: ignore

    def add_to_header(
        self,
        header: JOSEHeaderDict,
        include: bool = False
    ) -> None:
        """Updates a mapping of JOSE Header claims with the claims from the
        :class:~`JSONWebKey`.
        """
        if include and self.public:
            header['jwk'] = self.public.model_dump(
                mode='json',
                exclude_defaults=True,
                exclude_none=True,
                exclude_unset=True
            )
        header.update(
            self.root.model_dump(  # type: ignore
                mode='json',
                include={'kid', 'x5t', 'x5t_sha256', 'x5c', 'x5u', 'jku'},
                exclude_defaults=True,
                exclude_none=True,
                exclude_unset=True
            )
        )

    def can_verify(self, alg: JSONWebAlgorithm | None):
        """Return a boolean indicating if the key can verify a signature
        with the specified parameters.
        """
        return all([
            self.use in {None, 'sig'},
            not self.key_ops or ('verify' in self.key_ops),
            alg is None or self.root.supports_algorithm(alg)
        ])

    def is_asymmetric(self): # pragma: no cover
        return self.root.is_asymmetric()

    def is_public(self): # pragma: no cover
        return type(self.root) in (
            JSONWebKeyEdwardsCurvePublic,
            JSONWebKeyEllipticCurvePublic,
            JSONKeyRSAPublic,
            JSONWebKeySR25519Public,
        )

    def json(self): # type: ignore
        return self.model_dump_json( # pragma: no cover
            exclude_defaults=True
        )

    def decrypt(self, result: EncryptionResult):
        return self.root.decrypt(result)

    def derive_cek(
        self,
        alg: JSONWebAlgorithm,
        enc: JSONWebAlgorithm,
        private: 'JSONWebKey',
        public: 'JSONWebKey',
        apu: bytes = b'',
        apv: bytes = b'',
        ct: EncryptionResult | None = None
    ) -> 'JSONWebKey':
        return JSONWebKey(
            root=self.root.derive_cek(alg, enc, private, public, apu, apv, ct=ct)
        )

    def encrypt(
        self,
        pt: bytes,
        aad: bytes | None = None,
        alg: JSONWebAlgorithm | None = None
    ) -> EncryptionResult:
        alg = alg or self.alg
        assert alg is not None
        return self.root.encrypt(pt, aad, alg)

    def epk(self) -> tuple['JSONWebKey', Any]:
        """Create an ephemeral keypair to use in a key exchange."""
        public, private = self.root.epk()
        return JSONWebKey(root=public), private

    def sign(self, message: bytes, alg: JSONWebAlgorithm | None = None) -> AwaitableBytes:
        return self.root.sign(message, alg=alg) # type: ignore

    def thumbprint(self, using: ThumbprintHashAlgorithm):
        return self.root.thumbprint(using=using)

    def verify(self, signature: bytes, message: bytes, alg: Any):
        return self.root.verify(signature, message)

    def __str__(self):
        return self.root.model_dump_json(
            by_alias=True,
            exclude_defaults=True,
            exclude_none=True
        )

    def __bytes__(self):
        return bytes(self.root)

    def __hash__(self):
        return hash(self.thumbprint('sha256'))

    def __repr__(self):
        return f'<JSONWebKey: {{"kty": "{self.kty}", "alg": "{self.alg}", "crv": {self.crv}, "use": "{self.use}", "thumbprint": "{self.thumbprint('sha256')}"}}>'


# TODO: ugly
EncryptionResult.model_rebuild()