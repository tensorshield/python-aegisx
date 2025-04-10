import json
from typing import Any
from typing import Callable
from typing import Self
from typing import TypeVar

import pydantic
from libcanonical.types import AwaitableBool
from libcanonical.utils.encoding import b64encode
from libcanonical.utils.encoding import b64encode_json
from libcanonical.utils.encoding import b64decode_json

from aegisx.ext.jose.types import ContentEncodingError
from aegisx.ext.jose.types import InvalidPayload
from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JWSCompactEncoded
from ._jsonwebkey import JSONWebKey
from ._signedjws import SignedJWS


T = TypeVar('T')


class JSONWebSignature(
    pydantic.RootModel[
        SignedJWS |
        JWSCompactEncoded |
        dict[str, Any] |
        bytes
    ]
):
    
    @property
    def algorithms(self) -> set[JSONWebAlgorithm]:
        """The set of signing algorithms used to create the
        signatures.
        """
        return {signature.alg for signature in self.signatures}

    @property
    def headers(self):
        return [signature.header for signature in self.signatures]

    @property
    def payload(self) -> bytes:
        assert isinstance(self.root, SignedJWS)
        return self.root.payload

    @property
    def signatures(self):
        assert isinstance(self.root, SignedJWS)
        return tuple(self.root.signatures)
    
    @property
    def thumbprints(self) -> set[str]:
        """The set of thumbprints of all signing keys, if
        available.
        """
        return {
            signature.thumbprint()
            for signature in self.signatures
            if signature.has_public_key()
        }

    @classmethod
    def fromjwt(cls, jwt: Any, **protected: Any):
        protected.update({
            'cty': 'application/jwt',
            'typ': 'JWT'
        })
        return cls({'payload': bytes(jwt), 'claims': protected})

    def deserialize(self, cls: Callable[[bytes], T] = bytes):
        """Deserializes the content of the JWS."""
        assert isinstance(self.root, SignedJWS)
        return self.root.deserialize(cls=cls)

    def loads(self) -> dict[str, Any]:
        # TODO: This will only work for JWT
        try:
            data = b64decode_json(self.payload)
            if not isinstance(data, dict):
                raise InvalidPayload
            return data
        except (json.JSONDecodeError, TypeError, ValueError):
            raise ContentEncodingError

    def model_dump(self, **kwargs: Any):
        kwargs.setdefault('exclude_defaults', True)
        kwargs.setdefault('exclude_none', True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any):
        kwargs.setdefault('exclude_defaults', True)
        kwargs.setdefault('exclude_none', True)
        return super().model_dump_json(**kwargs)

    def model_post_init(self, _: Any) -> None:
        if isinstance(self.root, JWSCompactEncoded):
            self.root = SignedJWS.model_validate_compact(self.root) # type: ignore
        if isinstance(self.root, bytes):
            self.root = SignedJWS(
                payload=b64encode(self.root),
                claims={
                    'cty': 'application/octet-stream',
                }
            )
        if isinstance(self.root, dict):
            # If the root is a dictionary, then these are consided JWT claims.
            self.root = SignedJWS(
                payload=b64encode_json(self.root),
                claims={
                    'cty': 'application/jwt',
                    'typ': 'JWT'
                }
            )

    def serialize(self):
        assert isinstance(self.root, SignedJWS)
        return self.root.serialize()

    def sign(
        self,
        signer: JSONWebKey,
        alg: JSONWebAlgorithm | None = None,
        kid: str | None = None,
        typ: str | None =None,
        header: dict[str, Any] | None = None
    ) -> Self:
        assert isinstance(self.root, SignedJWS)
        alg = alg or signer.alg
        if alg is None:
            raise TypeError("The `alg` parameter can not be None.")
        self.root = self.root.sign(signer, alg, kid=kid, typ=typ, header=header)
        return self

    def verify(self, verifier: JSONWebKey):
        """Return a boolean indicating if at least one signature was valid."""
        assert isinstance(self.root, SignedJWS)
        if not self.root.signatures:
            return AwaitableBool(False)
        if not verifier.alg:
            raise ValueError(
                "The JSON Web Key (JWK) used to verify a JSON Web "
                "Signature (JWS) MUST specify the \"alg\" claim."
            )
        return self.root.verify(verifier)

    async def finalize(self):
        assert isinstance(self.root, SignedJWS)
        await self.root.finalize()
        return self

    def __await__(self):
        return self.finalize().__await__()

    def __str__(self):
        assert isinstance(self.root, SignedJWS)
        return self.root.serialize()

    def __repr__(self):
        return f'<JSONWebSignature: {repr(self.root)}'